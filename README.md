# Tapo P100
Tapo P100 is a Python library for controlling the Tp-link Tapo P100/P105/P110 plugs and L530/L510E bulbs.

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install PyP100.

```bash
pip3 install PyP100
```

## Usage
Plugs - P100, P105 etc.
```python
from PyP100.p100 import P100

plug = P100("192.168.X.X", "email@gmail.com", "Password123")

plug.turn_on()  # Sends the turn on request
plug.turn_off()  # Sends the turn off request
plug.get_device_info()  # Returns dict with all the device info
```
Bulbs - L510E, L530 etc.
```python
from PyP100.l530 import L530

bulb = L530("192.168.X.X", "email@gmail.com", "Password123")

# All the bulbs have the P100 functions and additionally allows for setting brightness, colour and colour temperature
bulb.set_brightness(100)  # Sends the set brightness request
bulb.set_color_temp(2700)  # Sets the colour temperature to 2700 Kelvin (Warm White)
bulb.set_hue_saturation(100, 100)  # Sets hue and saturation
```

Energy Monitoring plug - P110
```python
from PyP100.p110 import P110

plug = P110("192.168.X.X", "email@gmail.com", "Password123") #Creating a P110 plug object

# P110 has all PyP100 functions and additionally allows to query energy usage infos
plug.get_energy_usage()  # Returns a dict with all the energy usage statistics
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
