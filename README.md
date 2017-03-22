# SuperStat
A Linux based Operating Syatem monitoring utility, That can run both Pc's and mobiles.
---------------------------------------------------------------------------------------------------------------------------------


      Usage :

      -S              To show the live stats on the screen
                              (Options)
                      -d Disk partition name to monitor
                      -e NIC name to monitor
                      -t No of Top process

      -R              To send the stats to remote server (via tcp or udp)
                              (Options)
                      -a IP address or hostname
                      -p Port number
                      -i Interval between samples

      -L              To save the stats into local storage
                              (Options)
                      -i Interval between samples


Screenshots :

      Running in linux based desktop 
![alt tag](https://github.com/UlaganathanN/SuperStat/blob/master/Output.PNG)

      Running in android mobile
![alt tag](https://github.com/UlaganathanN/SuperStat/blob/master/MOutput.PNG)

      Visualize the OS metrics with grafana and influxDB by using -R flag
![alt tag](https://github.com/UlaganathanN/SuperStat/blob/master/GF.PNG)
