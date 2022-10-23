# Tapo P100
Tapo P100 is a Python library for controlling the Tp-link Tapo P100/P105/P110 plugs and L530/L510E bulbs.

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install PyP100.

```bash
pip3 install PyP100
```

## Usage

### Device initialization.
Any supported device can be initialized using the ``Tapo`` utility class.

```python
from PyP100 import Tapo

device = Tapo("192.168.X.X", "email@gmail.com", "Password123").get_device()
```

### Plugs - P100, P105 etc.

The plug devices have the following methods. Initialize the device as shown above.

```python
# Power on the device
device.turn_on()
# Power off the device
device.turn_off()
# Get a dictionary of device information
device.get_device_info()
```

### Bulbs - L510E, L530 etc.

In addition to the commands for the plugs above, additional commands are available for light bulbs.
Initialize the device as shown above.

```python
# Set brightness level
device.set_brightness(100)
# Set color temperature for the white light (2700 K, warm white)
device.set_color_temp(2700)
# Set hue and saturation for L530E
device.set_hue_saturation(100, 100)
```

### Energy Monitoring plug - P110

In addition to P100 plugs, the following command is available for P110 power monitoring plug.
Initialize the device as shown above.

```python
# Returns a dict with all the energy usage statistics
device.get_energy_usage()
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Contributers
[K4CZP3R](https://github.com/K4CZP3R)\
[Sonic74](https://github.com/sonic74)\
[shadow00](https://github.com/shadow00)\
[mochipon](https://github.com/mochipon)\
[realzoulou](https://github.com/realzoulou)\
[arrival-spring](https://github.com/arrival-spring)\
[wlp7s0](https://github.com/wlp7s0)\
[pnuu](https:/github.com/pnuu)

## License
[MIT](https://choosealicense.com/licenses/mit/)
