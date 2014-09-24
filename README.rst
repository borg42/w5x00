Linux Kernel driver for WIZnet W5200 and W5500
==============================================

This is a linux kernel driver for WIZnet W5200 and W5500. It is based on
an early development version of the W5500.

The driver is tested on Linux 3.4.90 (https://github.com/Tinkerforge/red-brick-linux-sunxi). It is currently in a working state for both W5200 and W5500, but please consider it to be still experimental.

Known missing parts:

* Speed improvements (currently the driver seems to be cpu bound)
* Errata 3 of W5200 not handled yet!
* PHY Reset of W5200 not implemented (not yet clear how we do it)
* Use MAC Address from EEPROM (RED Brick specific)
