# SuperStat
A Linux monitoring utility.
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

![alt tag](https://github.com/UlaganathanN/SuperStat/blob/master/Output.png)


visualize with grafana and influxDB by using -R flag
![alt tag](https://github.com/UlaganathanN/SuperStat/blob/master/GF.png)
