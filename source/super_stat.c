/*
*  	SuperStat v1.0
*	Dev: Ulaganathan Natrajan
*	(c) 2017
*
*	This library is free software; you can redistribute it and/or modify it
*	under the terms of the GNU Lesser General Public License as published by
*	the Free Software Foundation; either version 2.1 of the License, or (at
*	your option) any later version.
*
*	This library is distributed in the hope that it will be useful, but
*	WITHOUT ANY WARRANTY; without even the implied warranty of
*	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
*	Lesser General Public License for more details.
*
*	You should have received a copy of the GNU Lesser General Public
*	License along with this library; if not, write to the Free Software
*	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
*	USA.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <linux/version.h>
#include <sys/sysinfo.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define MAX_STATLEN 100000
#define MAX_TOPSTATLEN 5000
#define MAX_PARTITIONS 150
#define MAX_ETHERNETCON 50

//kernel Check
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
int kversion = -1;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0) && LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
int kversion = 1;
const char *lvg_scan = "%f %f %f";
const char *cpu_scan[5] = {"cpu %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld", "intr %lld", "ctxt %lld", "procs_running %lld", "procs_blocked %lld"};
const char *mem_scan[13]={"MemTotal: %lld kB", "Buffers: %lld kB", "Cached: %lld kB", "SwapCached: %lld kB", "MemFree: %lld kB", "Active: %lld kB", "Inactive: %lld kB", "HighTotal: %lld kB", "HighFree: %lld kB", "LowTotal: %lld kB", "LowFree: %lld kB", "SwapTotal: %lld kB", "SwapFree: %lld kB"};
const char *dsk_scan = "%d %d %s %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld";
const char *net_scan = "%s %lld %lld %d %d %d %d %d %d %lld %lld %d %d %d %d %d %d";
const char *con_scan = "%s %d %d %d %lld %lld %lld %lld %d %d %d %lld %lld %lld";
#else
int kversion = 2;
const char *lvg_scan = "%f %f %f";
const char *cpu_scan[5] = {"cpu %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld", "intr %lld", "ctxt %lld", "procs_running %lld", "procs_blocked %lld"};
const char *mem_scan[13]={"MemTotal: %lld kB", "Buffers: %lld kB", "Cached: %lld kB", "SwapCached: %lld kB", "MemFree: %lld kB", "Active: %lld kB", "Inactive: %lld kB", "HighTotal: %lld kB", "HighFree: %lld kB", "LowTotal: %lld kB", "LowFree: %lld kB", "SwapTotal: %lld kB", "SwapFree: %lld kB"};
const char *dsk_scan = "%d %d %s %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld";
const char *net_scan = "%s %lld %lld %d %d %d %d %d %d %lld %lld %d %d %d %d %d %d";
const char *con_scan = "%s %d %d %d %d %lld %lld %lld %lld %d %d %d %lld %lld %lld %d";
#endif

//custom typedef
typedef long long int llint;

//Global variables
static char timestamp[64], current_stat_top[MAX_TOPSTATLEN], reuse_stat[MAX_STATLEN], *ip, *mname, d_filter[200], e_filter[200], format[200];
static int n_partitions = 0, n_ethconnections = 0, stat_interval = 1, send_interval = 5, true = 1, port = 0, current_column=13, file_handle=0, file_column_limit = 250, r_sockfd=0, r_hostlen=0, d_f_pos=-1, e_f_pos=-1, n_top=5, c_ops=-1;
static FILE *stat_file[50], *conf_file;
struct sockaddr_in r_hostaddr;
struct hostent *r_host;

//statistics structs
struct cpu_stats
{
	llint user, nice, system, idle, iowait, irq, softirq, steal, guest, guestnice, intr, ctxt, procr, procb;
};

struct mem_stats
{
	llint total, used, free, buffer, cached, swapc, active, inactive, hight, highf, lowt, lowf, swapt, swapf;
};

struct disk_stats
{
	char dname[100];
	llint readc, readm, reads, readt, writec, writem, writes, writet, ioip, iot, iowt;
};

struct net_stats
{
	char ename[200];
	llint brecived, precived, btransmit, ptransmit, activeopens, passiveopens, attemptfails, estabresets, currentestab, retransegs, inerrors, outresets;
};

struct load_avg
{
	float onemin, fvmin, ftnmin;
};

struct cpu_stats cstats;
struct mem_stats mstats;
struct disk_stats dstats[MAX_PARTITIONS];
struct net_stats nstats[MAX_ETHERNETCON];

//Contains
int contains(char *source, char *find)
{
	char *exist;
	if(source == NULL || find == NULL)
	return 0;
	exist = strstr(source, find);
	if(exist != NULL)
	{
		return 1;
	}
	return 0;
}

//ReplaceAll
char *replace_all(char *source, char *orig, char *rep)
{
	char *outStr, *p;
	unsigned long pos = 0, replen = 0, origlen = 0;
	if(source == NULL || orig == NULL || rep == NULL)
	return source;
	p = strstr(source, orig);
	if(p == NULL)
	return source;
	replen = strlen(rep);
	origlen = strlen(orig);
	pos = (p - source) + replen;
	outStr = malloc(1 * sizeof(char));
	while(p != NULL)
	{
		outStr = realloc(outStr ,(strlen(source) + replen + 1));
		*outStr = '\0';
		strcat(outStr, source);
		sprintf(outStr + (p - source), "%s%s", rep, p + origlen);
		strcpy(source, outStr);
		p = strstr(source + pos, orig);
		pos = (p - source) + replen;
	}
	free(outStr);
	return source;
}

//socket connect
void connect_rhost(char *ip, int port, int type)
{
	if(type)
	r_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	else
	r_sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (r_sockfd < 0) 
	fprintf(stderr, "\nERROR: Opening socket %s", ip);
	r_host = gethostbyname(ip);
	if (r_host == NULL) 
	{
		fprintf(stderr,"\nERROR, No such host %s", ip);
		exit(0);
	}
	bzero((char *) &r_hostaddr, sizeof(r_hostaddr));
	r_hostaddr.sin_family = AF_INET;
	bcopy((char *)r_host->h_addr, (char *)&r_hostaddr.sin_addr.s_addr, r_host->h_length);
	r_hostaddr.sin_port = htons(port);
	r_hostlen = sizeof(r_hostaddr);
}

static void get_cpu_stat(struct cpu_stats *cpustat)
{
	FILE *file = fopen("/proc/stat", "r");
	if (file)
	{
		char buffer[MAX_STATLEN];
		while (fgets(buffer, MAX_STATLEN, file))
		{
			if(contains(buffer, "cpu "))
			{
				sscanf(buffer, cpu_scan[0],
				&cpustat->user, &cpustat->nice, &cpustat->system,
				&cpustat->idle, &cpustat->iowait, &cpustat->irq,
				&cpustat->softirq, &cpustat->steal, &cpustat->guest, &cpustat->guestnice);
			}else if(!contains(buffer, "cpu")){
				if(contains(buffer, "intr")){
					sscanf(buffer, cpu_scan[1], &cpustat->intr);
				}else if(contains(buffer, "ctxt")){
					sscanf(buffer, cpu_scan[2], &cpustat->ctxt);
				}else if(contains(buffer, "procs_r")){
					sscanf(buffer, cpu_scan[3], &cpustat->procr);
				}else if(contains(buffer, "procs_b")){
					sscanf(buffer, cpu_scan[4], &cpustat->procb);
				}
			}
		}
		pclose(file);
	}
}

static void get_mem_stat(struct mem_stats *memstat)
{
	FILE *file = fopen("/proc/meminfo", "r");
	if (file)
	{
		char buffer[MAX_STATLEN];
		while (fgets(buffer, MAX_STATLEN, file))
		{
			sscanf(buffer, mem_scan[0], &memstat->total);
			sscanf(buffer, mem_scan[1], &memstat->buffer);
			sscanf(buffer, mem_scan[2], &memstat->cached);
			sscanf(buffer, mem_scan[3], &memstat->swapc);
			sscanf(buffer, mem_scan[4], &memstat->free);
			sscanf(buffer, mem_scan[5], &memstat->active);
			sscanf(buffer, mem_scan[6], &memstat->inactive);
			sscanf(buffer, mem_scan[7], &memstat->hight);
			sscanf(buffer, mem_scan[8], &memstat->highf);
			sscanf(buffer, mem_scan[9], &memstat->lowt);
			sscanf(buffer, mem_scan[10], &memstat->lowf);
			sscanf(buffer, mem_scan[11], &memstat->swapt);
			sscanf(buffer, mem_scan[12], &memstat->swapf);
		}
		memstat->used = memstat->total - memstat->free;
		pclose(file);
	}
}

static void get_disk_stat(struct disk_stats *diskstat)
{
	FILE *file = fopen("/proc/diskstats", "r");
	if (file)
	{
		char buffer[MAX_STATLEN];
		int dummy;
		n_partitions=0;
		while (fgets(buffer, MAX_STATLEN, file))
		{
			if(n_partitions > MAX_PARTITIONS)
			break;
			if(!contains(buffer, "ram") && !contains(buffer, "loop"))
			{
				sscanf(buffer, dsk_scan, &dummy, &dummy, &diskstat[n_partitions].dname, &diskstat[n_partitions].readc, &diskstat[n_partitions].readm, &diskstat[n_partitions].reads, &diskstat[n_partitions].readt, &diskstat[n_partitions].writec, &diskstat[n_partitions].writem, &diskstat[n_partitions].writes, &diskstat[n_partitions].writet, &diskstat[n_partitions].ioip, &diskstat[n_partitions].iot, &diskstat[n_partitions].iowt);
				if(d_f_pos==-1){
					if(contains(buffer, d_filter))
					{
						d_f_pos=n_partitions;
					}
				}
				n_partitions++;
			}   
		}
		pclose(file);
	}
}

static void get_net_stat(struct net_stats *netstat)
{
	FILE *file = fopen("/proc/net/dev", "r");
	char buffer[MAX_STATLEN];
	int dummy;
	if (file)
	{
		n_ethconnections = 0;
		while (fgets(buffer, MAX_STATLEN, file))
		{
			if(n_ethconnections > MAX_ETHERNETCON)
			break;
			if(contains(buffer, ":")){
				sscanf(replace_all(buffer, ":", " "), net_scan, &netstat[n_ethconnections].ename, &netstat[n_ethconnections].brecived, &netstat[n_ethconnections].precived, &dummy, &dummy, &dummy, &dummy, &dummy, &dummy, &netstat[n_ethconnections].btransmit, &netstat[n_ethconnections].ptransmit, &dummy, &dummy, &dummy, &dummy, &dummy, &dummy);
				if(e_f_pos==-1){
					if(contains(buffer, e_filter))
					{
						e_f_pos=n_ethconnections;
					}
				}
				n_ethconnections++;
			}
		}
		pclose(file);
	}

	file = fopen("/proc/net/snmp", "r");
	if (file)
	{
		char dummychar[10];
		while (fgets(buffer, MAX_STATLEN, file))
		{
			if(contains(buffer, "Tcp"))
			{	
				fgets(buffer, MAX_STATLEN, file);
				sscanf(buffer, con_scan, &dummychar, &dummy, &dummy, &dummy, &dummy, &netstat[0].activeopens, &netstat[0].passiveopens, &netstat[0].attemptfails, &netstat[0].estabresets, &netstat[0].currentestab, &dummy, &dummy, &netstat[0].retransegs, &netstat[0].inerrors, &netstat[0].outresets, &dummy);
			}
		}
		pclose(file);
	}
}

static void get_load_avg(struct load_avg *ldvg)
{
	FILE *file;
	char buffer[MAX_STATLEN];
	file = fopen("/proc/loadavg", "r");
	if(file)
	{
		while (fgets(buffer, MAX_STATLEN, file))
		{
			sscanf(buffer, lvg_scan, &ldvg->onemin, &ldvg->fvmin, &ldvg->ftnmin);
		}
		pclose(file);
	}
}

//Top stat collection
void *get_top()
{
	FILE *file = popen("top -d 1", "r");;

	char buffer[1024], header[1024], top_stat[MAX_TOPSTATLEN], mname[200], ttimestamp[64];
	int line = 1, marker = 0;
	mname[200] = '\0';
	gethostname(mname, 199);
	time_t g_time;
	if (file)
	{
		while(true)
		{
			g_time = time(0);
			strftime (ttimestamp, 64, "%m-%d-%Y %H:%M:%S", localtime (&g_time));
			while (fgets(buffer, 1024, file))
			{
				if(!marker)
				{
					if(contains(buffer, "PID"))
					{
						marker = 1;
						char *end = strstr(buffer, "COMMAND");
						int endlen = (end-buffer)+7;
						buffer[endlen]='\0';
						strncpy(header, buffer+6, endlen);
						sprintf(top_stat, "\n|\x1B[35mTOP%02d  : \x1B[34m%s\n", n_top, header);
						strcat(top_stat, "\x1B[0m");
						continue;
					}
				}
				if(marker && line < n_top+1)
				{
					if(!contains(buffer, "PID"))
					{
						if(c_ops){
							strcat(top_stat,ttimestamp);
						}else{
							strcat(top_stat,"|\t");
						}
						strcat(top_stat, buffer);
						line++;
						continue;
					}
				}
				if(line > n_top)
				{
					fseek(stdin, 0, SEEK_END);
					marker=0;
					line = 1;
					break;
				}
			}
			strcpy(current_stat_top, top_stat);
			memset(top_stat, 0, MAX_TOPSTATLEN);
			sleep(stat_interval);
			//printf("%s\n\n", current_stat_top);
		}
		pclose(file);
	}
}

void custom_strcat_remote(char *mname, const char *gname, const char *variable, double value)
{
	char metric[512];
	if ((value != value)||value<0)
	value = 0.00;
	sprintf(metric, format, gname, variable, mname, value, timestamp);
	sendto(r_sockfd, metric, strlen(metric), 0, (struct sockaddr *)&r_hostaddr, r_hostlen);
	//printf("%s", metric);
}

void custom_strcat_local(char *reuse_stat, float value)
{
	char tmp[512];
	sprintf(tmp, "%.2f,", value);
	strcat(reuse_stat, tmp);
}

void custom_strcat_print(char *reuse_stat, float value)
{
	char tmp[512];
	sprintf(tmp, "   %05.2f ", value);
	strcat(reuse_stat, tmp);
}
// To Print Statistics
void *get_stat_print()
{
	struct cpu_stats ocstats, comstat;
	struct disk_stats odstats[MAX_PARTITIONS];
	struct net_stats onstats[MAX_ETHERNETCON];
	struct load_avg ldavgstat;
	char vname[1024];
	float overalltotal = 0;
	
	get_cpu_stat(&ocstats);
	get_disk_stat((struct disk_stats *)&odstats);
	get_net_stat((struct net_stats *)&onstats);
	sleep(stat_interval);
	printf("\n\033[?7l\x1B[33m***********************************************************************************************\n*\t\t\t\t\tSuperStat v1.0\t\t\t\t\t      *\n***********************************************************************************************\x1B[0m");
	while(true)
	{
		sprintf(timestamp, "%d", time(NULL));
		get_cpu_stat(&cstats);
		get_mem_stat(&mstats);
		get_disk_stat((struct disk_stats *)&dstats);
		get_net_stat((struct net_stats *)&nstats);
		get_load_avg(&ldavgstat);	

		comstat.user = cstats.user - ocstats.user;
		comstat.system = cstats.system - ocstats.system;
		comstat.idle = cstats.idle - ocstats.idle;
		comstat.nice = cstats.nice - ocstats.nice;
		comstat.steal = cstats.steal - ocstats.steal;
		comstat.iowait = cstats.iowait - ocstats.iowait;
		comstat.softirq = cstats.softirq - ocstats.softirq;
		comstat.irq = cstats.irq - ocstats.irq;
		comstat.intr = cstats.intr - ocstats.intr;
		comstat.ctxt = cstats.ctxt - ocstats.ctxt;
		overalltotal = comstat.user + comstat.system + comstat.nice + comstat.steal + comstat.iowait + comstat.idle;
		strcat(reuse_stat, "\n|---------------------------------------------------------------------------------------------|");
		strcat(reuse_stat, "\n|\x1B[35mCPU%%   : \x1B[34musr    sys    iow    nic    ste    idl    ttl   \x1B[35mSYS:\x1B[34m irq  intr   cntx   pr  pb      \x1B[0m|");
		sprintf(vname, "\n|        %05.2f  %05.2f  %05.2f  %05.2f  %05.2f  %05.2f  %05.2f   |   %02lld  %04lld   %04lld   %02lld  %02lld   ", (comstat.user / overalltotal) * 100, (comstat.system / overalltotal) * 100, (comstat.iowait / overalltotal) * 100, (comstat.nice / overalltotal) * 100, (comstat.steal / overalltotal) * 100, (comstat.idle / overalltotal) * 100, ((comstat.user + comstat.system + comstat.nice + comstat.iowait) / overalltotal) * 100, comstat.irq, comstat.intr, comstat.ctxt, cstats.procr, cstats.procb);
		strcat(reuse_stat, vname);
		strcat(reuse_stat, "\n|---------------------------------------------------------------------------------------------|");
		strcat(reuse_stat, "\n|\x1B[35mMEM(G) : \x1B[34mttl    usd     swpc    buf     cac     free    act     iact    swpt    swpf         \x1B[0m|");
		sprintf(vname, "\n|        %06.2f  %06.2f  %06.2f  %06.2f  %06.2f  %06.2f  %06.2f  %06.2f  %06.2f  %06.2f   ", mstats.total/1024.0/1024.0, mstats.used/1024.0/1024.0, mstats.swapc/1024.0/1024.0, mstats.buffer/1024.0/1024.0, mstats.cached/1024.0/1024.0, mstats.free/1024.0/1024.0, mstats.active/1024.0/1024.0, mstats.inactive/1024.0/1024.0, mstats.swapt/1024.0/1024.0, mstats.swapf/1024.0/1024.0);
		strcat(reuse_stat, vname);
		strcat(reuse_stat, "\n|---------------------------------------------------------------------------------------------|");
		strcat(reuse_stat, "\n|\x1B[35mDISK   : \x1B[34mdname   rd/s     wr/s     rdK/s    wrK/s    IOprg    avgQs    %%util    IOwait       \x1B[0m|");
		strcat(reuse_stat, "\n|         ");
		strcat(reuse_stat, dstats[d_f_pos].dname);
		strcat(reuse_stat, " ");
		custom_strcat_print((char *)&reuse_stat, (dstats[d_f_pos].readc - odstats[d_f_pos].readc));
		custom_strcat_print((char *)&reuse_stat, (dstats[d_f_pos].writec - odstats[d_f_pos].writec));
		custom_strcat_print((char *)&reuse_stat, ((dstats[d_f_pos].reads - odstats[d_f_pos].reads)*512)/1024.0);
		custom_strcat_print((char *)&reuse_stat, ((dstats[d_f_pos].writes - odstats[d_f_pos].writes)*512)/1024.0);
		custom_strcat_print((char *)&reuse_stat, dstats[d_f_pos].ioip - odstats[d_f_pos].ioip);
		custom_strcat_print((char *)&reuse_stat, (float)(dstats[d_f_pos].iowt - odstats[d_f_pos].iowt) / (float)(stat_interval * 1000));
		custom_strcat_print((char *)&reuse_stat, ((dstats[d_f_pos].iot - odstats[d_f_pos].iot) * 100) / (float)(stat_interval * 1000));
		custom_strcat_print((char *)&reuse_stat, dstats[d_f_pos].iowt - odstats[d_f_pos].iowt);
		strcat(reuse_stat, "   \n|---------------------------------------------------------------------------------------------|");
		strcat(reuse_stat, "      \n|\x1B[35mNET(M) : \x1B[34mename   brecv    btrans    tput     \x1B[35mTCP:\x1B[34m  ao   po   af  er   ce   rt  ie  or        \x1B[0m|");
		sprintf(vname, "\n|         %s    %05.2f    %05.2f    %05.2f      |    %02d   %02d   %02d  %02d  %02d   %02d  %02d  %02d   ", nstats[e_f_pos].ename, (nstats[e_f_pos].brecived - onstats[e_f_pos].brecived)/1024.0/1024.0, (nstats[e_f_pos].btransmit - onstats[e_f_pos].btransmit)/1024.0/1024.0, ((nstats[e_f_pos].btransmit - onstats[e_f_pos].btransmit)/1024.0/1024.0)+((nstats[e_f_pos].brecived - onstats[e_f_pos].brecived)/1024.0/1024.0), nstats[0].activeopens - onstats[0].activeopens, nstats[0].passiveopens - onstats[0].passiveopens, nstats[0].attemptfails - onstats[0].attemptfails, nstats[0].estabresets - onstats[0].estabresets, nstats[0].currentestab, nstats[0].retransegs - onstats[0].retransegs, nstats[0].inerrors - onstats[0].inerrors, nstats[0].outresets - onstats[0].outresets);
		strcat(reuse_stat, vname);
		strcat(reuse_stat, "\n|---------------------------------------------------------------------------------------------|");
		printf(replace_all(replace_all(replace_all(reuse_stat, "-1", "0.00"), "-nan", "0.00"), "nan", "0.00"));
		printf("%s|---------------------------------------------------------------------------------------------|                          \n", current_stat_top);
		printf("\033[%dA", 16+n_top);
		
		ocstats = cstats;
		memcpy(&odstats, &dstats, sizeof(dstats));
		memcpy(&onstats, &nstats, sizeof(nstats));
		memset(reuse_stat, 0, MAX_STATLEN);
		sleep(stat_interval);
	}
}

//For Streaming
void *get_stat_remote()
{
	struct cpu_stats ocstats, comstat;
	struct disk_stats odstats[MAX_PARTITIONS];
	struct net_stats onstats[MAX_ETHERNETCON];
	struct load_avg ldavgstat;
	char vname[200];
	int x = 0;

	get_cpu_stat(&ocstats);
	get_disk_stat((struct disk_stats *)&odstats);
	get_net_stat((struct net_stats *)&onstats);
	sleep(stat_interval);
	while(true)
	{
		sprintf(timestamp, "%d", time(NULL));
		get_cpu_stat(&cstats);
		get_mem_stat(&mstats);
		get_disk_stat((struct disk_stats *)&dstats);
		get_net_stat((struct net_stats *)&nstats);
		get_load_avg(&ldavgstat);	
		comstat.user = cstats.user - ocstats.user;
		comstat.system = cstats.system - ocstats.system;
		comstat.idle = cstats.idle - ocstats.idle;
		comstat.nice = cstats.nice - ocstats.nice;
		comstat.steal = cstats.steal - ocstats.steal;
		comstat.iowait = cstats.iowait - ocstats.iowait;
		comstat.softirq = cstats.softirq - ocstats.softirq;
		comstat.irq = cstats.irq - ocstats.irq;
		comstat.guest = cstats.guest - ocstats.guest;
		comstat.intr = cstats.intr - ocstats.intr;
		comstat.ctxt = cstats.ctxt - ocstats.ctxt;
		float overalltotal = comstat.user + comstat.system + comstat.nice + comstat.iowait + comstat.idle;
		custom_strcat_remote(mname, "loadavg", "1min", ldavgstat.onemin);
		custom_strcat_remote(mname, "loadavg", "5min", ldavgstat.fvmin);
		custom_strcat_remote(mname, "loadavg", "15min", ldavgstat.ftnmin);
		custom_strcat_remote(mname, "cpu", "user", (comstat.user / overalltotal) * 100);
		custom_strcat_remote(mname, "cpu", "sys", (comstat.system / overalltotal) * 100);
		custom_strcat_remote(mname, "cpu", "idle", (comstat.idle / overalltotal) * 100);
		custom_strcat_remote(mname, "cpu", "nice", (comstat.nice / overalltotal) * 100);
		custom_strcat_remote(mname, "cpu", "iowait", (comstat.iowait / overalltotal) * 100);
		custom_strcat_remote(mname, "cpu", "total", ((comstat.user + comstat.system + comstat.nice + comstat.iowait) / overalltotal) * 100);
		custom_strcat_remote(mname, "sys", "intr", comstat.intr);
		custom_strcat_remote(mname, "sys", "ctxt", comstat.ctxt);
		custom_strcat_remote(mname, "sys", "procrun", cstats.procr);
		custom_strcat_remote(mname, "sys", "procblc", cstats.procb);
		custom_strcat_remote(mname, "memory", "used", mstats.used);
		custom_strcat_remote(mname, "memory", "free", mstats.free);
		custom_strcat_remote(mname, "memory", "total", mstats.total);
		custom_strcat_remote(mname, "memory", "swap", mstats.swapc);
		custom_strcat_remote(mname, "memory", "buffer", mstats.buffer);
		custom_strcat_remote(mname, "memory", "cached", mstats.cached);
		for(x = 0; x<n_partitions; x++)
		{
			sprintf(vname, "%s.readsPerSec", dstats[x].dname);
			custom_strcat_remote(mname, "disk", vname, (dstats[x].readc - odstats[x].readc));
			sprintf(vname, "disk", "%s.timeTakenPerReadMS", dstats[x].dname);
			custom_strcat_remote(mname, "disk", vname, ((dstats[x].readt - odstats[x].readt))/(float)(dstats[x].readc - odstats[x].readc));
			sprintf(vname, "%s.readsKBPerSec", dstats[x].dname);
			custom_strcat_remote(mname, "disk", vname, ((dstats[x].reads - odstats[x].reads)*512)/1024.0);
			sprintf(vname, "%s.writesPerSec", dstats[x].dname);
			custom_strcat_remote(mname, "disk", vname, (dstats[x].writec - odstats[x].writec));
			sprintf(vname, "%s.timeTakenPerWriteMS", dstats[x].dname);
			custom_strcat_remote(mname, "disk", vname, ((dstats[x].writet - odstats[x].writet))/(float)(dstats[x].writec - odstats[x].writec));
			sprintf(vname, "%s.writesKBPerSec", dstats[x].dname);
			custom_strcat_remote(mname, "disk", vname, ((dstats[x].writes - odstats[x].writes)*512)/1024.0);
			sprintf(vname, "%s.IOInprogress", dstats[x].dname);
			custom_strcat_remote(mname, "disk", vname, dstats[x].ioip - odstats[x].ioip);
			sprintf(vname, "%s.avgRequestSize", dstats[x].dname);
			custom_strcat_remote(mname, "disk", vname, (float)((dstats[x].reads - odstats[x].reads) + (dstats[x].writes - odstats[x].writes))/ (float)((dstats[x].readc - odstats[x].readc) + (dstats[x].writec - odstats[x].writec)));
			sprintf(vname, "%s.avgQueueSize", dstats[x].dname);
			custom_strcat_remote(mname, "disk", vname, (float)(dstats[x].iowt - odstats[x].iowt) / (float)(stat_interval * 1000));
			sprintf(vname, "%s.percentUtil", dstats[x].dname);
			custom_strcat_remote(mname, "disk", vname, ((dstats[x].iot - odstats[x].iot) * 100) / (float)(stat_interval * 1000));
			sprintf(vname, "%s.weightedTimeOnIO", dstats[x].dname);
			custom_strcat_remote(mname, "disk", vname, dstats[x].iowt - odstats[x].iowt);
		}
		for(x = 0; x<n_ethconnections; x++)
		{
			sprintf(vname, "%s.bytesRecived", nstats[x].ename);
			custom_strcat_remote(mname, "network", vname, nstats[x].brecived - onstats[x].brecived);
			sprintf(vname, "%s.bytesTransmit", nstats[x].ename);
			custom_strcat_remote(mname, "network", vname, nstats[x].btransmit - onstats[x].btransmit);
			sprintf(vname, "%s.packetsRecived", nstats[x].ename);
			custom_strcat_remote(mname, "network", vname, nstats[x].precived);
			sprintf(vname, "%s.packetsTransmit", nstats[x].ename);
			custom_strcat_remote(mname, "network", vname, nstats[x].ptransmit);
		}
		custom_strcat_remote(mname, "network", "activeconopens", nstats[0].activeopens - onstats[0].activeopens);
		custom_strcat_remote(mname, "network", "passiveconopens", nstats[0].passiveopens - onstats[0].passiveopens);
		custom_strcat_remote(mname, "network", "attemptfails", nstats[0].attemptfails - onstats[0].attemptfails);
		custom_strcat_remote(mname, "network", "establishresets", nstats[0].estabresets - onstats[0].estabresets);
		custom_strcat_remote(mname, "network", "currentestablish", nstats[0].currentestab);
		custom_strcat_remote(mname, "network", "retranssegs", nstats[0].retransegs - onstats[0].retransegs);
		custom_strcat_remote(mname, "network", "inerrors", nstats[0].inerrors - onstats[0].inerrors);
		custom_strcat_remote(mname, "network", "outresets", nstats[0].outresets - onstats[0].outresets);
		ocstats = cstats;
		memcpy(&odstats, &dstats, sizeof(dstats));
		memcpy(&onstats, &nstats, sizeof(nstats));
		sleep(send_interval);
		//printf("%s\n", current_stat);
	}
}

//For local storage
void move_next_file()
{
	if((current_column/file_column_limit)>file_handle)
	{
		fprintf(stat_file[file_handle], "%s\n", replace_all(replace_all(replace_all(reuse_stat, "-1", "0.00"), "-nan", "0.00"), "nan", "0.00"));
		fflush(stat_file[file_handle]);
		file_handle++;
		memset(reuse_stat, 0, MAX_STATLEN);
		fprintf(stat_file[file_handle], "%s,", timestamp);
	}
}

void *get_stat_local()
{
	struct cpu_stats ocstats, comstat;
	struct disk_stats odstats[MAX_PARTITIONS];
	struct net_stats onstats[MAX_ETHERNETCON];
	struct load_avg ldavgstat;
	char vname[200], filename[200];
	int i_check=1, x = 0, column_size=0, no_of_files=1, p=1, is_conf_req=0;
	mkdir("Outputs",0777);
	if(!fopen("Outputs/graphConf.csv","r"))
	{
		is_conf_req=1;
		conf_file = fopen("Outputs/graphConf.csv","w");
	}
	time_t g_time;
	get_disk_stat((struct disk_stats *)&dstats);
	get_net_stat((struct net_stats *)&nstats);
	column_size = 19+(n_partitions*11)+(n_ethconnections*4);
	if(column_size>file_column_limit)
	{
		no_of_files = column_size/file_column_limit;
		if(column_size%file_column_limit!=0)
		no_of_files++;
	}
	for(x=0; x<no_of_files; x++)
	{
		time_t g_time = time(0);
		strftime (timestamp, 64, "%m-%d-%Y %H:%M:%S", localtime (&g_time));
		sprintf(filename, "Outputs/%s_%s_%d.csv", mname, replace_all(replace_all(timestamp,":","-")," ","_"), x);
		stat_file[x] = fopen(filename, "w");
	}
	sprintf(filename, "Outputs/%s_%s_Top.csv", mname, replace_all(replace_all(timestamp,":","-")," ","_"));
	stat_file[no_of_files] = fopen(filename, "w");
	strcpy(timestamp, "time");
	fprintf(stat_file[file_handle], "%s", "time,cpu.lavg1,cpu.lavg5,cpu.lavg10,cpu.user,cpu.system,cpu.idle,cpu.iowait,cpu.total,sys.intr,sys.ctxt,sys.procr,sys.procb,memory.used,memory.free,memory.total,memory.swapc,memory.buffer,memory.cached,");
	if(is_conf_req)
	{
		fprintf(conf_file,"%s","IsPerfMon,ServerType,ID,ParamName,DisplayName,StatisticsType,SecAxisTitle,Formula,CM,RA,Color,Selected,Address\n");
		fprintf(conf_file, "N,Fedora,P%04d,cpu.lavg1,cpu.lavg1,lAvg,,Null,N,Null,TEAL,Y,null\n", p, p); p++;
		fprintf(conf_file, "N,Fedora,P%04d,cpu.lavg5,cpu.lavg5,lAvg,,Null,N,Null,TURQUOISE,Y,null\n", p, p); p++;
		fprintf(conf_file, "N,Fedora,P%04d,cpu.lavg10,cpu.lavg10,lAvg,,Null,N,Null,OLIVE GREEN,Y,null\n", p, p); p++;
		fprintf(conf_file, "N,Fedora,P%04d,cpu.user,cpu.user,Cpu,,Null,N,Null,LIGHT BLUE,Y,null\n", p, p); p++;
		fprintf(conf_file, "N,Fedora,P%04d,cpu.system,cpu.system,Cpu,,Null,N,Null,BLUE,Y,null\n", p, p); p++;
		fprintf(conf_file, "N,Fedora,P%04d,cpu.idle,cpu.idle,Cpu,,Null,N,Null,DARK TEAL,Y,null\n", p, p); p++;
		fprintf(conf_file, "N,Fedora,P%04d,cpu.iowait,cpu.iowait,Cpu,,Null,N,Null,PALE BLUE,Y,null\n", p, p); p++;
		fprintf(conf_file, "N,Fedora,P%04d,cpu.total,cpu.total,Cpu,,Null,N,Null,RED,Y,null\n", p, p); p++;
		fprintf(conf_file, "N,Fedora,P%04d,sys.intr,sys.intr,Sys,,Null,N,Null,TEAL,Y,null\n", p, p); p++;
		fprintf(conf_file, "N,Fedora,P%04d,sys.ctxt,sys.ctxt,Sys,,Null,N,Null,RED,Y,null\n", p, p); p++;
		fprintf(conf_file, "N,Fedora,P%04d,sys.procr,sys.procr,Sys,,Null,N,Null,OLIVE,Y,null\n", p, p); p++;
		fprintf(conf_file, "N,Fedora,P%04d,sys.procb,sys.procb,Sys,,Null,N,Null,PALE,Y,null\n", p, p); p++;
		fprintf(conf_file, "N,Fedora,P%04d,memory.used,memory.used,Memory,MB,P%04d:/:1024,N,Null,RED,Y,null\n", p, p); p++;
		fprintf(conf_file, "N,Fedora,P%04d,memory.free,memory.free,Memory,MB,P%04d:/:1025,N,Null,BRIGHT GREEN,Y,null\n", p, p); p++;
		fprintf(conf_file, "N,Fedora,P%04d,memory.total,memory.total,Memory,MB,P%04d:/:1026,N,Null,BROWN,Y,null\n", p, p); p++;
		fprintf(conf_file, "N,Fedora,P%04d,memory.swapc,memory.swapc,Memory,MB,P%04d:/:1027,N,Null,INDIGO,Y,null\n", p, p); p++;
		fprintf(conf_file, "N,Fedora,P%04d,memory.buffer,memory.buffer,Memory,MB,P%04d:/:1028,N,Null,LIGHT ORANGE,Y,null\n", p, p); p++;
		fprintf(conf_file, "N,Fedora,P%04d,memory.cached,memory.cached,Memory,MB,P%04d:/:1029,N,Null,TEAL,Y,null\n", p, p); p++;
	}
	for(x = 0; x<n_partitions; x++)
	{
		current_column +=11; 
		fprintf(stat_file[file_handle], "disk.%s.readsPerSec,", dstats[x].dname);
		fprintf(stat_file[file_handle], "disk.%s.timeTakenPerReadMS,", dstats[x].dname);
		fprintf(stat_file[file_handle], "disk.%s.readsKBPerSec,", dstats[x].dname);
		fprintf(stat_file[file_handle], "disk.%s.writesPerSec,", dstats[x].dname);
		fprintf(stat_file[file_handle], "disk.%s.timeTakenPerWriteMS,", dstats[x].dname);
		fprintf(stat_file[file_handle], "disk.%s.writesKBPerSec,", dstats[x].dname);
		fprintf(stat_file[file_handle], "disk.%s.IOInprogress,", dstats[x].dname);
		fprintf(stat_file[file_handle], "disk.%s.avgRequestSize,", dstats[x].dname);
		fprintf(stat_file[file_handle], "disk.%s.avgQueueSize,", dstats[x].dname);
		fprintf(stat_file[file_handle], "disk.%s.percentUtil,", dstats[x].dname);
		fprintf(stat_file[file_handle], "disk.%s.weightedTimeOnIO,", dstats[x].dname);
		move_next_file();
		if(is_conf_req)
		{
			fprintf(conf_file, "N,Fedora,P%04d,disk.%s.readsPerSec,disk.%s.readsPerSec,%s,,Null,N,Null,RED,N,Null\n", p, dstats[x].dname, dstats[x].dname, dstats[x].dname); p++;
			fprintf(conf_file, "N,Fedora,P%04d,disk.%s.timeTakenPerReadMS,disk.%s.timeTakenPerReadMS,%s,,Null,N,Null,BRIGHT GREEN,N,Null\n", p, dstats[x].dname, dstats[x].dname, dstats[x].dname); p++;
			fprintf(conf_file, "N,Fedora,P%04d,disk.%s.readsKBPerSec,disk.%s.readsKBPerSec,%s,,Null,N,Null,BLUE,N,Null\n", p, dstats[x].dname, dstats[x].dname, dstats[x].dname); p++;
			fprintf(conf_file, "N,Fedora,P%04d,disk.%s.writesPerSec,disk.%s.writesPerSec,%s,,Null,N,Null,YELLOW,N,Null\n", p, dstats[x].dname, dstats[x].dname, dstats[x].dname); p++;
			fprintf(conf_file, "N,Fedora,P%04d,disk.%s.timeTakenPerWriteMS,disk.%s.timeTakenPerWriteMS,%s,,Null,N,Null,PINK,N,Null\n", p, dstats[x].dname, dstats[x].dname, dstats[x].dname); p++;
			fprintf(conf_file, "N,Fedora,P%04d,disk.%s.writesKBPerSec,disk.%s.writesKBPerSec,%s,,Null,N,Null,TURQUOISE,N,Null\n", p, dstats[x].dname, dstats[x].dname, dstats[x].dname); p++;
			fprintf(conf_file, "N,Fedora,P%04d,disk.%s.IOInprogress,disk.%s.IOInprogress,%s,,Null,N,Null,OLIVE GREEN,N,Null\n", p, dstats[x].dname, dstats[x].dname, dstats[x].dname); p++;
			fprintf(conf_file, "N,Fedora,P%04d,disk.%s.avgRequestSize,disk.%s.avgRequestSize,%s,,Null,N,Null,BROWN,N,Null\n", p, dstats[x].dname, dstats[x].dname, dstats[x].dname); p++;
			fprintf(conf_file, "N,Fedora,P%04d,disk.%s.avgQueueSize,disk.%s.avgQueueSize,%s,,Null,N,Null,PLUM,N,Null\n", p, dstats[x].dname, dstats[x].dname, dstats[x].dname); p++;
			fprintf(conf_file, "N,Fedora,P%04d,disk.%s.percentUtil,disk.%s.percentUtil,%s,,Null,N,Null,INDIGO,N,Null\n", p, dstats[x].dname, dstats[x].dname, dstats[x].dname); p++;
			fprintf(conf_file, "N,Fedora,P%04d,disk.%s.weightedTimeOnIO,disk.%s.weightedTimeOnIO,%s,,Null,N,Null,DARK GREEN,N,Null\n", p, dstats[x].dname, dstats[x].dname, dstats[x].dname); p++;
		}
	}
	move_next_file();
	for(x = 0; x<n_ethconnections; x++)
	{
		current_column +=4;
		fprintf(stat_file[file_handle], "network.%s.bytesRecived,", nstats[x].ename);
		fprintf(stat_file[file_handle], "network.%s.bytesTransmit,", nstats[x].ename);
		fprintf(stat_file[file_handle], "network.%s.packetsRecived,", nstats[x].ename);
		fprintf(stat_file[file_handle], "network.%s.packetsTransmit,", nstats[x].ename);
		move_next_file();
		if(is_conf_req)
		{
			fprintf(conf_file, "N,Fedora,P%04d,network.%s.bytesRecived,network.%s.bytesRecived,%s,Mbps,(:P%04d:*:8:):/:(1024*1024),N,Null,ORANGE,Y,Null\n", p, nstats[x].ename, nstats[x].ename, nstats[x].ename, p); p++;
			fprintf(conf_file, "N,Fedora,P%04d,network.%s.packetsRecived,network.%s.packetsRecived,%s,,Null,N,Null,TEAL,N,Null\n", p, nstats[x].ename, nstats[x].ename, nstats[x].ename, p); p++;
			fprintf(conf_file, "N,Fedora,P%04d,network.%s.packetsTransmit,network.%s.packetsTransmit,%s,,Null,N,Null,PALE BLUE,N,Null\n", p, nstats[x].ename, nstats[x].ename, nstats[x].ename); p++;
			fprintf(conf_file, "N,Fedora,P%04d,network.%s.bytesTransmit,network.%s.bytesTransmit,%s,Mbps,(:P%04d:*:8:):/:(1024*1024),N,Null,AQUA,Y,Null\n", p, nstats[x].ename, nstats[x].ename, nstats[x].ename); p++;
			fprintf(conf_file, "N,Fedora,P%04d,network.%s.Throughput,network.%s.Throughput,%s,,P%04d:+:P%04d,N,Null,BROWN,Y,Null\n", p, nstats[x].ename, nstats[x].ename, nstats[x].ename, p-4, p-3); p++;
		}
	}
	move_next_file();
	fprintf(stat_file[file_handle], "%s", "network.activeconopens,network.passiveconopens,network.attemptfails,network.establishresets,network.currentestablish,network.retranssegs,network.inerrors,network.outresets\n");
	fflush(stat_file[file_handle]);
	if(is_conf_req)
	{
		fprintf(conf_file, "N,Fedora,P%04d,network.activeconopens,network.activeconopens,Network,,Null,N,Null,PINK,Y,Null\n", p);  p++;
		fprintf(conf_file, "N,Fedora,P%04d,network.passiveconopens,network.passiveconopens,Network,,Null,N,Null,SEA GREEN,Y,Null\n", p);  p++;
		fprintf(conf_file, "N,Fedora,P%04d,network.attemptfails,network.attemptfails,Network,,Null,N,Null,ORANGE,Y,Null\n", p);  p++;
		fprintf(conf_file, "N,Fedora,P%04d,network.establishresets,network.establishresets,Network,,Null,N,Null,DARK RED,Y,Null\n", p);  p++;
		fprintf(conf_file, "N,Fedora,P%04d,network.currentestablish,network.currentestablish,Network,,Null,N,Null,RED,Y,Null\n", p);  p++;
		fprintf(conf_file, "N,Fedora,P%04d,network.retranssegs,network.retranssegs,Network,,Null,N,Null,INDIGO,Y,Null\n", p);  p++;
		fprintf(conf_file, "N,Fedora,P%04d,network.inerrors,network.inerrors,Network,,Null,N,Null,RED,Y,Null\n", p);  p++;
		fprintf(conf_file, "N,Fedora,P%04d,network.outresets,network.outresets,Network,,Null,N,Null,TEAL,Y,Null\n", p);  p++;
		fflush(conf_file);
		fclose(conf_file);
	}
	get_cpu_stat(&ocstats);
	get_disk_stat((struct disk_stats *)&odstats);
	get_net_stat((struct net_stats *)&onstats);
	sleep(stat_interval);
	while(true)
	{
		g_time = time(0);
		strftime (timestamp, 64, "%m-%d-%Y %H:%M:%S", localtime (&g_time));
		get_cpu_stat(&cstats);
		get_mem_stat(&mstats);
		get_disk_stat((struct disk_stats *)&dstats);
		get_net_stat((struct net_stats *)&nstats);
		get_load_avg(&ldavgstat);
		file_handle = 0;
		current_column=13;
		comstat.user = cstats.user - ocstats.user;
		comstat.system = cstats.system - ocstats.system;
		comstat.idle = cstats.idle - ocstats.idle;
		comstat.nice = cstats.nice - ocstats.nice;
		comstat.steal = cstats.steal - ocstats.steal;
		comstat.iowait = cstats.iowait - ocstats.iowait;
		comstat.softirq = cstats.softirq - ocstats.softirq;
		comstat.irq = cstats.irq - ocstats.irq;
		comstat.intr = cstats.intr - ocstats.intr;
		comstat.ctxt = cstats.ctxt - ocstats.ctxt;
		float overalltotal = comstat.user + comstat.system + comstat.nice + comstat.iowait + comstat.idle;
		
		custom_strcat_local((char *)&reuse_stat, ldavgstat.onemin);
		custom_strcat_local((char *)&reuse_stat, ldavgstat.fvmin);
		custom_strcat_local((char *)&reuse_stat, ldavgstat.ftnmin);
		custom_strcat_local((char *)&reuse_stat, (comstat.user / overalltotal) * 100);
		custom_strcat_local((char *)&reuse_stat, (comstat.system / overalltotal) * 100);
		custom_strcat_local((char *)&reuse_stat, (comstat.idle / overalltotal) * 100);
		custom_strcat_local((char *)&reuse_stat, (comstat.iowait / overalltotal) * 100);
		custom_strcat_local((char *)&reuse_stat, ((comstat.user + comstat.system + comstat.nice + comstat.iowait) / overalltotal) * 100);
		custom_strcat_local((char *)&reuse_stat, comstat.intr);
		custom_strcat_local((char *)&reuse_stat, comstat.ctxt);
		custom_strcat_local((char *)&reuse_stat, cstats.procr);
		custom_strcat_local((char *)&reuse_stat, cstats.procb);
		custom_strcat_local((char *)&reuse_stat, mstats.used);
		custom_strcat_local((char *)&reuse_stat, mstats.free);
		custom_strcat_local((char *)&reuse_stat, mstats.total);
		custom_strcat_local((char *)&reuse_stat, mstats.swapc);
		custom_strcat_local((char *)&reuse_stat, mstats.buffer);
		custom_strcat_local((char *)&reuse_stat, mstats.cached);
		if(i_check<=0)
		{
			fprintf(stat_file[file_handle], "%s,%s", timestamp, replace_all(replace_all(replace_all(reuse_stat, "-1", "0.00"), "-nan", "0.00"), "nan", "0.00"));
			fflush(stat_file[file_handle]);
		}
		memset(reuse_stat, 0, MAX_STATLEN);
		for(x = 0; x<n_partitions; x++)
		{
			current_column +=11;
			custom_strcat_local((char *)&reuse_stat, (dstats[x].readc - odstats[x].readc));
			custom_strcat_local((char *)&reuse_stat, ((dstats[x].readt - odstats[x].readt))/(float)(dstats[x].readc - odstats[x].readc));
			custom_strcat_local((char *)&reuse_stat, ((dstats[x].reads - odstats[x].reads)*512)/1024.0);
			custom_strcat_local((char *)&reuse_stat, (dstats[x].writec - odstats[x].writec));
			custom_strcat_local((char *)&reuse_stat, ((dstats[x].writet - odstats[x].writet))/(float)(dstats[x].writec - odstats[x].writec));
			custom_strcat_local((char *)&reuse_stat, ((dstats[x].writes - odstats[x].writes)*512)/1024.0);
			custom_strcat_local((char *)&reuse_stat, dstats[x].ioip - odstats[x].ioip);
			custom_strcat_local((char *)&reuse_stat, (float)((dstats[x].reads - odstats[x].reads) + (dstats[x].writes - odstats[x].writes))/ (float)((dstats[x].readc - odstats[x].readc) + (dstats[x].writec - odstats[x].writec)));
			custom_strcat_local((char *)&reuse_stat, (float)(dstats[x].iowt - odstats[x].iowt) / (float)(stat_interval * 1000));
			custom_strcat_local((char *)&reuse_stat, ((dstats[x].iot - odstats[x].iot) * 100) / (float)(stat_interval * 1000));
			custom_strcat_local((char *)&reuse_stat, dstats[x].iowt - odstats[x].iowt);
			if(i_check<=0)
			{
				move_next_file();
			}
		}
		if(i_check<=0)
		{
			move_next_file();
		}
		for(x = 0; x<n_ethconnections; x++)
		{
			current_column +=4;
			custom_strcat_local((char *)&reuse_stat, nstats[x].brecived - onstats[x].brecived);
			custom_strcat_local((char *)&reuse_stat, nstats[x].btransmit - onstats[x].btransmit);
			custom_strcat_local((char *)&reuse_stat, nstats[x].precived);
			custom_strcat_local((char *)&reuse_stat, nstats[x].ptransmit);
			if(i_check<=0)
			{
				move_next_file();
			}
		}
		if(i_check<=0)
		{
			move_next_file();
		}
		custom_strcat_local((char *)&reuse_stat, nstats[0].activeopens - onstats[0].activeopens);
		custom_strcat_local((char *)&reuse_stat, nstats[0].passiveopens - onstats[0].passiveopens);
		custom_strcat_local((char *)&reuse_stat, nstats[0].attemptfails - onstats[0].attemptfails);
		custom_strcat_local((char *)&reuse_stat, nstats[0].estabresets - onstats[0].estabresets);
		custom_strcat_local((char *)&reuse_stat, nstats[0].currentestab);
		custom_strcat_local((char *)&reuse_stat, nstats[0].retransegs - onstats[0].retransegs);
		custom_strcat_local((char *)&reuse_stat, nstats[0].inerrors - onstats[0].inerrors);
		custom_strcat_local((char *)&reuse_stat, nstats[0].outresets - onstats[0].outresets);
		if(i_check<=0)
		{
			fprintf(stat_file[file_handle], "%s\n", replace_all(replace_all(replace_all(reuse_stat, "-1", "0.00"), "-nan", "0.00"), "nan", "0.00"));
			fflush(stat_file[file_handle]);
			sprintf(current_stat_top,"%s",replace_all(current_stat_top, " ", ","));
			while(contains(current_stat_top, ",,"))
			{
				sprintf(current_stat_top,"%s",replace_all(current_stat_top, ",,", ","));
			}
			sprintf(current_stat_top,"%s",replace_all(current_stat_top, ",,", ","));
			fprintf(stat_file[no_of_files], "%s", current_stat_top);
			fflush(stat_file[no_of_files]);
			i_check=send_interval;
		}
		i_check--;
		ocstats = cstats;
		memcpy(&odstats, &dstats, sizeof(dstats));
		memcpy(&onstats, &nstats, sizeof(nstats));
		memset(reuse_stat, 0, MAX_STATLEN);
		sleep(stat_interval);
		//printf("%s\n", current_stat);
	}
}

void help()
{
	printf("\n***************************************************************\n\t\tSuperStat v1.0\n\t\tDeveloper: Ulaganathan Natrajan\n\t\tUlaganathan.n@hotmail.com\n***************************************************************\n");
	printf("\nUsage :     (-S args ... | -R args ... | -L args ... )\n\n-S\t\tTo show the live stats on the screen\n\t\t\t(Options)\n\t\t-d Disk partition name to monitor\n\t\t-e NIC name to monitor\n\t\t-t No of Top process\n\n-R\t\tTo send the stats to remote server (via udp or tcp)\n\t\t\t(Options)\n\t\t-a IP address or hostname\n\t\t-p Port number\n\t\t-i Interval between samples\n\n-L\t\tTo save the stats into local storage\n\t\t\t(Options)\n\t\t-i Interval between samples\n");
}

int main(int argc, char *argv[])
{
	char mnamewd[200];
	mnamewd[199] = '\0';
	gethostname(mnamewd, 198);
	mname = replace_all(mnamewd ,".", "-");
	int x;
	strcpy(d_filter, "sda ");
	strcpy(e_filter, "lo ");
	
	for(x=2; x<argc; x=x+2)
	{
		if(x+1>argc)
		help();
		if(contains(argv[x],"-d")||contains(argv[x],"-D"))
		{
			strcpy(d_filter, argv[x+1]);
		}else if(contains(argv[x],"-e")||contains(argv[x],"-E"))
		{
			strcpy(e_filter, argv[x+1]);
		}else if(contains(argv[x],"-i")||contains(argv[x],"-I"))
		{
			send_interval = atoi(argv[x+1]);
		}else if(contains(argv[x],"-a")||contains(argv[x],"-A"))
		{
			ip = argv[x+1];
		}else if(contains(argv[x],"-p")||contains(argv[x],"-P"))
		{
			port = atoi(argv[x+1]);
		}else if(contains(argv[x],"-t")||contains(argv[x],"-T"))
		{
			n_top = atoi(argv[x+1]);
			if(n_top>30)
			n_top=30;
		}
	}
	if(send_interval<=0)
	send_interval = 1;
	pthread_t stat_thread, stat_top_thread;
	if( pthread_create( &stat_top_thread , NULL, &get_top, NULL) < 0)
	{
		printf("\nUnable to Start Top Stat Collection Thread!");
		return -1;
	}
	if(contains(argv[1],"-H")||contains(argv[1],"-h")||argc == 1)
	{
		help();
		return -1;
	}
	else if(contains(argv[1],"-s")||contains(argv[1],"-S"))
	{
		c_ops=0;
		if( pthread_create( &stat_thread , NULL, &get_stat_print, NULL) < 0)
		{
			printf("\nUnable to Start Stat Collection Thread!");
			return -1;
		}
		while (true)
		{
			sleep(send_interval);
		}
	}
	else if(contains(argv[1],"-r")||contains(argv[1],"-R"))
	{
		c_ops=1;
		if( argc>=6)
		{
			strcpy(format, "%s,metric_name=%s,host_name=%s metric_value=%.2f %s000000000\n");
			connect_rhost(ip, port, 1);
			printf("\nStreaming data to ip : %s on port %d with the interval %d ...\nNOTE: 1%% of CPU overhead will be there due to metric transfer over network\n", ip, port, send_interval);
			if( pthread_create( &stat_thread , NULL, &get_stat_remote, NULL) < 0)
			{
				printf("\nUnable to Start Stat Collection Thread!");
				return -1;
			}
			printf("\nStat Collection Thread started!");
			sleep(send_interval+1);
			printf("\nSending Data...\nPress Ctrl+C to Quit");
			while (true)
			{
				sleep(send_interval);
			}
		}
		else
		{
			help();
			return -1;
		}
	}
	else if(contains(argv[1],"-l")||contains(argv[1],"-L"))
	{
		c_ops=2;
		printf("\nSaving stats to local with interval of %d ...", send_interval);
		if( pthread_create( &stat_thread , NULL, &get_stat_local, NULL) < 0)
		{
			printf("\nUnable to Start Stat Collection Thread!");
			return -1;
		}
		printf("\nStat Collection Thread started!");
		printf("\nWriting Data...\nPress Ctrl+C to Quit");
		while (true)
		{
			sleep(send_interval);
		}
		return 0;
	}
}
