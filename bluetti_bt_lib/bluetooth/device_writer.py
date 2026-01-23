import asyncio
import logging
from typing import Any, Callable
import async_timeout
from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError
from bleak_retry_connector import BleakClientWithServiceCache, establish_connection

from bluetti_bt_lib.bluetooth.encryption import BluettiEncryption, Message, MessageType
from bluetti_bt_lib.const import WRITE_UUID, NOTIFY_UUID
from bluetti_bt_lib.base_devices import BluettiDevice
from bluetti_bt_lib.utils.privacy import mac_loggable


class DeviceWriterConfig:
    def __init__(self, timeout: int = 15, use_encryption: bool = False):
        self.timeout = timeout
        self.use_encryption = use_encryption


class DeviceWriter:
    """
    DeviceWriter with encryption support.
    Supports both old interface (BleakClient) and new interface (MAC address).
    """

    def __init__(
        self,
        bleak_client_or_mac: BleakClient | str,
        bluetti_device: BluettiDevice,
        config: DeviceWriterConfig = DeviceWriterConfig(),
        lock: asyncio.Lock = asyncio.Lock(),
        future_builder_method: Callable[[], asyncio.Future[Any]] | None = None,
    ):
        # Support both old interface (BleakClient) and new interface (MAC address)
        if isinstance(bleak_client_or_mac, str):
            # New interface: MAC address
            self.mac = bleak_client_or_mac
            self.provided_client = None
            self.create_future = future_builder_method or (lambda: asyncio.Future())
        else:
            # Old interface: BleakClient (for backward compatibility)
            self.provided_client = bleak_client_or_mac
            self.mac = bleak_client_or_mac.address
            self.create_future = lambda: asyncio.Future()

        self.bluetti_device = bluetti_device
        self.config = config
        self.polling_lock = lock

        self.logger = logging.getLogger(
            f"{__name__}.{mac_loggable(self.mac).replace(':', '_')}"
        )

        self.device = None
        self.client = None
        self.has_notifier = False
        self.encryption = BluettiEncryption()

    async def write(self, field: str, value: Any):
        # Check if encryption is enabled but not yet supported in old code path
        if self.config.use_encryption and self.provided_client is not None:
            self.logger.warning(
                "Encryption requires new DeviceWriter interface. "
                "Pass MAC address instead of BleakClient."
            )

        available_fields = [f.name for f in self.bluetti_device.fields]
        if field not in available_fields:
            self.logger.error("Field not supported")
            return

        command = self.bluetti_device.build_write_command(field, value)

        if command is None:
            self.logger.error("Field is not writeable")
            return

        self.logger.debug("Writing to device register")

        async with self.polling_lock:
            try:
                async with async_timeout.timeout(self.config.timeout):
                    # Use provided client if available (old interface)
                    if self.provided_client is not None:
                        self.client = self.provided_client
                        self.logger.debug("Using provided BleakClient")
                    else:
                        # New interface: find and connect to device
                        self.logger.debug("Searching for device")
                        self.device = await BleakScanner.find_device_by_address(
                            self.mac, timeout=5
                        )

                        if self.device is None:
                            self.logger.error("Device not found")
                            return

                        self.logger.debug("Connecting to device")
                        self.client = await establish_connection(
                            BleakClientWithServiceCache,
                            self.device,
                            self.device.name or "Unknown Device",
                            max_attempts=10,
                        )

                    self.logger.debug("Connected to device")

                    # Set up notification handler for encryption handshake
                    if self.config.use_encryption and not self.has_notifier:
                        await self.client.start_notify(
                            NOTIFY_UUID, self._notification_handler
                        )
                        self.has_notifier = True
                        self.logger.debug("Notification handler setup complete")

                    # Wait for encryption handshake to complete
                    if self.config.use_encryption:
                        max_wait = 30  # seconds
                        waited = 0
                        while not self.encryption.is_ready_for_commands:
                            await asyncio.sleep(1)
                            waited += 1
                            if waited >= max_wait:
                                self.logger.error("Encryption handshake timeout")
                                return
                            if waited % 5 == 0:
                                self.logger.debug("Waiting for encryption handshake...")

                    # Prepare command bytes
                    command_bytes = bytes(command)

                    # Encrypt command if needed
                    if self.config.use_encryption:
                        if not self.encryption.is_ready_for_commands:
                            self.logger.error("Encryption not ready")
                            return
                        command_bytes = self.encryption.aes_encrypt(
                            command_bytes, self.encryption.secure_aes_key, None
                        )

                    self.logger.debug("Writing command: %s", command)

                    await self.client.write_gatt_char(
                        WRITE_UUID,
                        command_bytes,
                    )

                    self.logger.debug("Write successful")

            except TimeoutError:
                self.logger.warning("Timeout")
                return None
            except BleakError as err:
                self.logger.warning("Bleak error: %s", err)
                return None
            except BaseException as err:
                self.logger.warning("Unknown error: %s", err)
                return None
            finally:
                if self.has_notifier:
                    try:
                        await self.client.stop_notify(NOTIFY_UUID)
                        self.logger.debug("Stopped notifier")
                    except:
                        pass
                    self.has_notifier = False

                # Only disconnect if we created the connection
                if self.provided_client is None and self.client:
                    await self.client.disconnect()
                    self.logger.debug("Disconnected from device")

                # Reset encryption keys
                if self.config.use_encryption:
                    self.encryption.reset()

    async def _notification_handler(self, _: int, data: bytearray):
        """Handle Bluetooth notifications for encryption handshake"""
        self.logger.debug("Got new data")

        if self.config.use_encryption:
            message = Message(data)

            if message.is_pre_key_exchange:
                message.verify_checksum()

                if message.type == MessageType.CHALLENGE:
                    challenge_response = self.encryption.msg_challenge(message)
                    await self.client.write_gatt_char(WRITE_UUID, challenge_response)
                    return

                if message.type == MessageType.CHALLENGE_ACCEPTED:
                    self.logger.debug("Challenge accepted")
                    return

            if self.encryption.unsecure_aes_key is None:
                self.logger.error(
                    "Received encrypted message before key initialization"
                )
                return

            key, iv = self.encryption.getKeyIv()
            decrypted = Message(self.encryption.aes_decrypt(message.buffer, key, iv))

            if decrypted.is_pre_key_exchange:
                decrypted.verify_checksum()

                if decrypted.type == MessageType.PEER_PUBKEY:
                    peer_pubkey_response = self.encryption.msg_peer_pubkey(decrypted)
                    await self.client.write_gatt_char(WRITE_UUID, peer_pubkey_response)
                    return

                if decrypted.type == MessageType.PUBKEY_ACCEPTED:
                    self.encryption.msg_key_accepted(decrypted)
                    return
