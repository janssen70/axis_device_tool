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
Furthermore the -r option is usefull to see the flow of formatted data, especially for requests to ```/vapix/services```.

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
| IOOn | Set an output pin |
| IOOff | Reset an output pin |
| VirtualIOOn | Set a virtual input |
| VirtualIOOff | Reset a virtual input |
| ManualTriggerOn | Set the manual trigger |
| ManualTriggerOff | Reset the manual trigger |
| IOPulse | Set, wait, reset an output pin |
| MQTTActivate | Enable the MQTT client |
| MQTTDectivate | Disable the MQTT client |
| MQTTConfig | Configure the MQTT client |
| MQTTGetConfig | Retrieve the MQTT client configuration |
| MQTTGetEventPublications | Retrieve the MQTT event publications |
| MQTTRemoveEventPublications | Remove all MQTT event publications |
| MQTTAddEventPublications | Configure a new list of MQTT event publications |
| MQTTAddEventPublication | Add a single MQTT event publications |
| Wait | Inserts a delay, usefull when executing a series of functions |



Event information
-----------------
The output from GetEventInfo shows each events' "nice name" followed by a specification for use directly in event metadata subscriptions. For example, given this output:

```
CameraApplicationPlatform
 Blocked View Detection - Blocked View Detection    eventtopic=axis:CameraApplicationPlatform/BlockedViewDetection/BlockedViewDetection
 Loitering Guard - Loitering Guard: Any Profile eventtopic=axis:CameraApplicationPlatform/LoiteringGuard/Camera1ProfileANY
 Loitering Guard - Loitering Guard: Profile 1   eventtopic=axis:CameraApplicationPlatform/LoiteringGuard/Camera1Profile1
 Video Motion Detection - VMD 4: Any Profile    eventtopic=axis:CameraApplicationPlatform/VMD/Camera1ProfileANY
 Video Motion Detection - VMD 4: Profile 1  eventtopic=axis:CameraApplicationPlatform/VMD/Camera1Profile1
```
You can start listening to VMD 4 detections for all profiles on the RTSP metadata stream as follows:

```
rtsp://a.b.c.d/axis-media/media.amp?video=0&audio=0&event=on&eventtopic=axis:CameraApplicationPlatform/VMD/Camera1ProfileANY
```

The [Axis Metadata Monitor](https://www.axis.com/developer-community/axis-metadata-monitor) is very usefull for this. A commandline alternative is my script [axis_websocket_events](https://github.com/janssen70/axis_websocket_events) which listens to the same events, but over websocket instead. It's README show it use for the same event. It is similar, you just need to leave out the RTSP-url specific "eventtopic=" prefix.



License
-------

This software is distributed under the MIT license.
