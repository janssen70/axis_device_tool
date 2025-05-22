axis_device_tool
----------------
Python script to perform operations on Axis devices.
Requires Python 3.8+. Some examples:

1. Get supported events from a device, specifying credentials and IP address:

  ```bash
  python3 device_tool.py -u root -p pass -c 192.168.1.3 -f GetEventInfo
  ```

2. As previous, but rely on the connection parameters of last eap-install.sh
  invocation (stored in .eap-install.cfg), which adds some convenience during
  [ACAP development](https://developer.axis.com/acap/)

  ```bash
  python3 device_tool.py -f GetEventInfo
  ```

3. As 2, but print summary of GetEventInfo instead:

  ```bash
  python3 device_tool.py -f GetEventInfo -d
  ```

4. Get serverreport of several cameras, using credentials from
  .eap-install.cfg on all devices

  ```bash
  python3 device_tool.py -c 192.168.1.3 -c 192.168.1.4 -c 192.168.1.5 -f GetServerReport
  ```

5. See more options, and actual credentials in use:

  ```bash
  python3 device_tool.py -h
  ```

6. Install ACAP (again), start it, wait two minutes, remove it

  ```bash
  python3 device_tool.py -f "UploadAcap(filename=youracap_0_8_5_armv7hf.eap)" -f ListAcaps -f "StartAcap(package=youracap)" -f "Wait(seconds=120)" -f "RemoveAcap(package=youracap)" -f ListAcaps
  ```

Supported operations
--------------------


| Name | Function |
| ---- | -------- |
| EnableSSH | Enables SSH on the device (needs Axis OS 5.60 or higher) |
| FactoryDefault | Performs factory default while keeping the IP address |
| GetEventInfo | Shows the list of supported events, for use in metadata subscription requests |
| GetServerReport | Create and download a serverreport |
| GetSomeInfo | Example parameter request, getting several items at once but not the full list |
| GetSystemLog | Retrieves the system log |
| HardfactoryDefault | Performs hard factory default |
| ListAcaps | Lists the installed ACAPs |
| ListFeatureFlags | Lists the supported feature flags |
| PerformTrace | Make the device perform a network trace |
| Reboot | Restarts the device |
| RemoveAcap | |
| RestartAcap | |
| StartAcap | |
| StopAcap | |
| UploadAcap | |
| Wait | Inserts a delay, usefull when executing a series of functions |


License
-------

This software is distributed under the MIT license.
