/***************************************************************************
 practica2.c
 Muestra las direciones Ethernet de la traza que se pasa como primer parametro.
 Debe complatarse con mas campos de niveles 2, 3, y 4 tal como se pida en el enunciado.
 Debe tener capacidad de dejar de analizar paquetes de acuerdo a un filtro.
 
 Compila: gcc -Wall -o practica2 practica2.c -lpcap, make
 Autor: Francisco Andreu Sanz
 2015 EPS-UAM 
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>

#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <inttypes.h>

/*Definicion de constantes ***********************************************/
#define ETH_ALEN      6      /* Tamano de direccion ethernet             */
#define ETH_HLEN      14     /* Tamano de cabecera ethernet              */
#define ETH_TLEN      2      /* Tamano del campo tipo ethernet           */
#define IP_VERIHL	1	
#define IP_TIPOSERV	1
#define IP_LONGTOT	2
#define IP_IDENTIF	2
#define VLAN_RES 2 
#define VLAN_TYPE 2 
#define IP_POS	2
#define IP_TVIDA	1
#define IP_PROT	1
#define IP_SUMCAB	2
#define IP_DIR1	4
#define IP_DIR2	4
#define IP_ETC	4
#define TCP_PDEST	2
#define TCP_PORIGEN	2
#define UDP_PDEST	2
#define UDP_PORIGEN	2
#define UDP_LONG	2
#define ETH_FRAME_MAX 1514   /* Tamano maximo trama ethernet (sin CRC)   */
#define ETH_FRAME_MIN 60     /* Tamano minimo trama ethernet (sin CRC)   */
#define ETH_DATA_MAX  (ETH_FRAME_MAX - ETH_HLEN) /* Tamano maximo y minimo de los datos de una trama ethernet*/
#define ETH_DATA_MIN  (ETH_FRAME_MIN - ETH_HLEN)
#define IP_ALEN 4			/* Tamano de direccion IP					*/
#define OK 0
#define ERROR 1

void f_analizar_paquete(uint8_t *usuario, const struct pcap_pkthdr* cabecera,const uint8_t* paquete);

void handleSignal(int nsignal);

typedef struct{
   int port;
   int popular;
   unsigned long tam;
}Port;

pcap_t* descr;
uint64_t contador=0;
uint8_t ipo_filtro[IP_ALEN]={0};
uint8_t ipd_filtro[IP_ALEN]={0};
unsigned int eo_filtro[ETH_ALEN]={0};
unsigned int ed_filtro[ETH_ALEN]={0};
uint16_t po_filtro=0;
uint16_t pd_filtro=0;
int j=0;/*Numero de puertos distintos*/
int k=0;/*Paquetes analizados*/
int s=1; /*Segundos pasados para analisis de ancho de banda*/
time_t anterior_seg=0;
suseconds_t anterior_miliseg=0;
time_t segundo_seg =0;
suseconds_t segundo_miliseg =0;
unsigned long tam_acumulado=0;

int num_udp=0;
int num_tcp=0;
int num_others=0;
int num_noip=0;
int num_ip=0;
int num_vlan=0;

int token=0;
int token_ipo=0;
int token_ipd=0;
int token_po=0;
int token_pd=0;
int token_eo=0;
int token_ed=0;
int token_t_i=0;
int token_des=0;

Port* ports;
FILE *f_Ethernet;
FILE* f_Flujo;
FILE* f_AnchoBanda;

void topFiveSize(){
	int i=0, t=j, aux_puerto=0, aux_popular=0, num=0;
        unsigned long aux_tam = 0;
	for(;num<j;num++){
		for(i=0;i<t-1;i++){
			if(ports[i].tam < ports[i+1].tam){
				aux_popular = ports[i].popular;
				aux_puerto = ports[i].port;
                                aux_tam = ports[i].tam;
				ports[i].popular = ports[i+1].popular;
				ports[i].port = ports[i+1].port;
                                ports[i].tam = ports[i+1].tam;
				ports[i+1].popular = aux_popular;
				ports[i+1].port = aux_puerto;
                                ports[i+1].tam = aux_tam;
			}
		}
		t=t-1;
	}

	printf("\nTopFiveSize:\n");

	for(i=0;i<5 && i<j;i++){
		printf("%d.%d con %ld\n", i+1,ports[i].port, ports[i].tam);
	}
}

void topFivePack(){
	int i=0, t=j, aux_puerto=0, aux_popular=0, num=0;
	for(;num<j;num++){
		for(i=0;i<t-1;i++){
			if(ports[i].popular < ports[i+1].popular){
				aux_popular = ports[i].popular;
				aux_puerto = ports[i].port;
				ports[i].popular = ports[i+1].popular;
				ports[i].port = ports[i+1].port;
				ports[i+1].popular = aux_popular;
				ports[i+1].port = aux_puerto;
			}
		}
		t=t-1;
	}

	printf("\nTopFivePack:\n");

	for(i=0;i<5 && i<j;i++){
		printf("%d.%d con %d\n", i+1,ports[i].port, ports[i].popular);
	}
}

void handleSignal(int nsignal){
	printf("Control C pulsado (%llu)\n", contador);
	printf("Se procesaron %llu paquetes.\n\n",contador);
	printf("Hay %d paquetes NO IP\n", num_noip);
	printf("Hay %d paquetes IP\n", num_ip);
	printf("Hay %d paquetes IP que no son ni TCP ni UDP\n", num_others);	
	printf("Hay %d paquetes IP/TCP\n", num_tcp);
	printf("Hay %d paquetes IP/UDP\n", num_udp);	
	printf("Hay un porcentaje de un %lf %% de paquetes IP con respecto al total.\n", (double)num_ip*100/(double)contador);
	printf("\tDentro de este porcentaje:\n");
	printf("\t\t-Hay un porcentaje de un %lf %% de paquetes TCP con respecto al total de ip.\n", (double) num_tcp*100.00/(double) num_ip);
	printf("\t\t-Hay un porcentaje de un %lf %% de paquetes UDP con respecto al total de ip.\n", (double) num_udp*100.00/(double)num_ip);
	printf("\t\t-Hay un porcentaje de un %lf %% de paquetes de otro tipo con respecto al total de ip.\n", (double)num_others*100.00/(double)num_ip);	
	printf("Hay un porcentaje de un %lf %% de paquetes NO IP con respecto al total.\n", (double)num_noip*100/(double)contador);
	printf("Por ultimo, el numero de TAGs VLAN encontrados ha sido: %d \n", num_vlan);
	topFivePack();
        topFiveSize();
	//caudal es el ancho banda			
	free(ports);
	pcap_close(descr);
	fclose(f_Ethernet);
	fclose(f_Flujo);
	fclose(f_AnchoBanda);
	exit(OK);
	
}

void add(int popular, int tam){	
	int flag = 0;
	int i;

	for(i=0; i < j; i++)
		if (ports[i].port == popular){
			ports[i].popular++;
                        ports[i].tam += tam;
			flag=1;
		}
	if (flag==0){
		ports[j].port = popular;
		ports[j].popular=1;
                ports[j].tam = tam;
		ports=(Port*)realloc(ports ,(j+2) * sizeof(Port));
		j++;
	}
}

int main(int argc, char **argv){

	char errbuf[PCAP_ERRBUF_SIZE];
	char entrada[256];
	int long_index=0,retorno=0;
	char opt;
	ports = (Port*)malloc(1 * sizeof(Port));
	f_Ethernet = fopen("Tam_Ethernet.txt", "w");
	f_Flujo = fopen("Tiempo_Flujo.txt", "w");
	f_AnchoBanda = fopen("Ancho_Banda.txt", "w");
        fprintf(f_Flujo, "No.\tSeg\n");
	fprintf(f_AnchoBanda, "Seg\tTam(Bytes)\n");
        fprintf(f_Ethernet, "No.\tTam(Bytes)\n");
	
	
	if(signal(SIGINT,handleSignal)==SIG_ERR){
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		exit(ERROR);
	}
	if(argc>1){
		if(strlen(argv[1])<256){
			strcpy(entrada,argv[1]);
		}
	}
	else {
		printf("Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD] [-etho ETH Origen] [-ethd ETH Destino]: %d\n",argv[0],argc);
		exit(ERROR);
	}
	static struct option options[] = {
		{"ipo",required_argument,0,'1'},
		{"ipd",required_argument,0,'2'},
		{"po",required_argument,0,'3'},
		{"pd",required_argument,0,'4'},
		{"h",no_argument,0,'5'},
		{"t", required_argument,0,'6'},
		{"i", required_argument,0,'7'},
		{"etho", required_argument,0,'8'},
		{"ethd", required_argument,0,'9'},
		{"des", no_argument,0,'a'},
		{0,0,0,0}
	};
	
	//Simple lectura por parametros por completar casos de error, ojo no cumple 100% los requisitos del enunciado!
	while ((opt = getopt_long_only(argc, argv,"1:2:3:4:5:6:7:8:9:a", options, &long_index )) != -1) {
		switch (opt) {
			case '1' : 
				if(sscanf(optarg,"%hhu.%"SCNu8".%"SCNu8".%"SCNu8"",&(ipo_filtro[0]),&(ipo_filtro[1]),&(ipo_filtro[2]),&(ipo_filtro[3]))!=IP_ALEN){
					printf("Error ipo_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD] [-etho ETH Origen] [-ethd ETH Destino]: %d\n",argv[0],argc); exit(ERROR);
				}
				token_ipo = 1;
				break;
			
			case '2' : 
				if(sscanf(optarg,"%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"",&(ipd_filtro[0]),&(ipd_filtro[1]),&(ipd_filtro[2]),&(ipd_filtro[3]))!=IP_ALEN){
					printf("Error ipd_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD] [-etho ETH Origen] [-ethd ETH Destino]: %d\n",argv[0],argc); exit(ERROR);
				}
				token_ipd = 1;

				break;
			
			case '3' : 
			if((po_filtro = atoi(optarg))==0){
							printf("Error o_filtro.Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD] [-etho ETH Origen] [-ethd ETH Destino]: %d\n",argv[0],argc); exit(ERROR);
						}
						token_po = 1;					
				break;
			
			case '4' : if((pd_filtro = atoi(optarg))==0){
							printf("Error pd_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD] [-etho ETH Origen] [-ethd ETH Destino]: %d\n",argv[0],argc); exit(ERROR);
						}	
						token_pd = 1;
				break;
				
			case '5' : printf("Ayuda. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD] [-etho ETH Origen] [-ethd ETH Destino]: %d\n",argv[0],argc); exit(ERROR);
				break;
			
			case '6' :
				sscanf(optarg, "%s",entrada);
				token = 0;

				token_t_i++;
				if(token_t_i>1){
					printf("Utiliza -t o -i no ambos\n"); exit(ERROR);
				}

				break;
			
			case '7' :
				sscanf(optarg, "%s",entrada);

				token_t_i++;
				if(token_t_i>1){
					printf("Utiliza -t o -i no ambos\n"); exit(ERROR);
				}

				if(strncmp(entrada,"eth", 3)==0){
					printf("La captura se hace con la interfaz de red en modo ETH\n");
					token=1;
				}
				else if(strncmp(entrada,"wlan", 4)==0){
					printf("La captura se hace con la interfaz de red en modo WLAN\n");
					token=2;
				}
				break;
			case '8' :if(sscanf(optarg,"%02X:%02X:%02X:%02X:%02X:%02X",&(eo_filtro[0]),&(eo_filtro[1]),&(eo_filtro[2]),&(eo_filtro[3]),&(eo_filtro[4]),&(eo_filtro[5]))!=ETH_ALEN){
							printf("Error eo_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD] [-etho ETH Origen] [-ethd ETH Destino]: %d\n",argv[0],argc); exit(ERROR);
						}	
					token_eo = 1;
				break;
			case '9' : if(sscanf(optarg,"%02X:%02X:%02X:%02X:%02X:%02X", &(ed_filtro[0]),&(ed_filtro[1]),&(ed_filtro[2]),&(ed_filtro[3]),&(ed_filtro[4]),&(ed_filtro[5]))!=ETH_ALEN){
							printf("Error ed_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD] [-etho ETH Origen] [-ethd ETH Destino]: %d\n",argv[0],argc); exit(ERROR);
						}	
					token_ed = 1;
				break;
			case 'a' : 
					token_des = 1;
				break;
			default: printf("Error.Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD] [-etho ETH Origen] [-ethd ETH Destino]: %d\n",argv[0],argc); exit(ERROR);
				break;
        }
	
    }
	//Simple comprobacion de la correcion de la lectura de parametros
	printf("Entrada: %s\n",entrada);	
	printf("Filtro:");
	//if(ipo_filtro[0]!=0)
		printf("ipo_filtro:%hhu.%hhu.%hhu.%hhu\t",ipo_filtro[0],ipo_filtro[1],ipo_filtro[2],ipo_filtro[3]);
	//if(ipd_filtro[0]!=0)
		printf("ipd_filtro:%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"\t",ipd_filtro[0],ipd_filtro[1],ipd_filtro[2],ipd_filtro[3]);
	if(po_filtro!=0)
		printf("po_filtro=%hu\t",po_filtro);
	if(pd_filtro!=0)
		printf("pd_filtro=%"SCNu16,pd_filtro);
	printf("\n\n");

	if (token == 0){
			if ( (descr = pcap_open_offline(entrada, errbuf)) == NULL){
				printf("Error: pcap_open_offline(): File: %s, %s %s %d.\n", argv[1],errbuf,__FILE__,__LINE__);
				exit(ERROR);
			}
			
			retorno = pcap_loop (descr,-1,f_analizar_paquete, (uint8_t*)&contador);
			if(retorno == -1){ 		//En caso de error
				printf("Error al capturar un paquete %s, %s %d.\n",pcap_geterr(descr),__FILE__,__LINE__);
				pcap_close(descr);
				exit(ERROR);
			}
			else if(retorno==-2){ //pcap_breakloop() no asegura la no llamada a la funcion de atencion para paquetes ya en el buffer
				printf("Llamada a %s %s %d.\n","pcap_breakloop()",__FILE__,__LINE__); 
			}
			else if(retorno == 0){
				printf("No hay mas paquetes o limite superado en %s %d.\n",__FILE__,__LINE__);
			}
	}
	else if (token == 1){
			if ( (descr = pcap_open_live("eth0",ETH_FRAME_MAX ,0,0, errbuf)) == NULL){
				printf("Error: pcap_open_offline(): File: %s, %s %s %d.\n", argv[1],errbuf,__FILE__,__LINE__);
				exit(ERROR);
			}
			
			retorno = pcap_loop (descr,-1,f_analizar_paquete, (uint8_t*)&contador);
			if(retorno == -1){ 		//En caso de error
				printf("Error al capturar un paquete %s, %s %d.\n",pcap_geterr(descr),__FILE__,__LINE__);
				pcap_close(descr);
				exit(ERROR);
			}
			else if(retorno==-2){ //pcap_breakloop() no asegura la no llamada a la funcion de atencion para paquetes ya en el buffer
				printf("Llamada a %s %s %d.\n","pcap_breakloop()",__FILE__,__LINE__); 
			}
			else if(retorno == 0){
				printf("No hay mas paquetes o limite superado en %s %d.\n",__FILE__,__LINE__);
			}
	}
	else if (token == 2){
			if ( (descr = pcap_open_live("wlan",ETH_FRAME_MAX ,0,0, errbuf)) == NULL){
				printf("Error: pcap_open_offline(): File: %s, %s %s %d.\n", argv[1],errbuf,__FILE__,__LINE__);
				exit(ERROR);
			}
			
			retorno = pcap_loop (descr,-1,f_analizar_paquete, (uint8_t*)&contador);
			if(retorno == -1){ 		//En caso de error
				printf("Error al capturar un paquete %s, %s %d.\n",pcap_geterr(descr),__FILE__,__LINE__);
				pcap_close(descr);
				exit(ERROR);
			}
			else if(retorno==-2){ //pcap_breakloop() no asegura la no llamada a la funcion de atencion para paquetes ya en el buffer
				printf("Llamada a %s %s %d.\n","pcap_breakloop()",__FILE__,__LINE__); 
			}
			else if(retorno == 0){
				printf("No hay mas paquetes o limite superado en %s %d.\n",__FILE__,__LINE__);
			}
	}	
	


	printf("_______________________\n\n");
	printf("Se procesaron %llu paquetes.\n\n",contador);
	printf("Hay %d paquetes NO IP\n", num_noip);
	printf("Hay %d paquetes IP\n", num_ip);
	printf("Hay %d paquetes IP que no son ni TCP ni UDP\n", num_others);	
	printf("Hay %d paquetes IP/TCP\n", num_tcp);
	printf("Hay %d paquetes IP/UDP\n", num_udp);	
	printf("Hay un porcentaje de un %lf %% de paquetes IP con respecto al total.\n", (double)num_ip*100/(double)contador);
	printf("\tDentro de este porcentaje:\n");
	printf("\t\t-Hay un porcentaje de un %lf %% de paquetes TCP con respecto al total de ip.\n", (double) num_tcp*100.00/(double) num_ip);
	printf("\t\t-Hay un porcentaje de un %lf %% de paquetes UDP con respecto al total de ip.\n", (double) num_udp*100.00/(double)num_ip);
	printf("\t\t-Hay un porcentaje de un %lf %% de paquetes de otro tipo con respecto al total de ip.\n", (double)num_others*100.00/(double)num_ip);	
	printf("Hay un porcentaje de un %lf %% de paquetes NO IP con respecto al total.\n", (double)num_noip*100/(double)contador);
	printf("Por ultimo, el numero de TAGs VLAN encontrados ha sido: %d \n", num_vlan);		
	topFivePack();
        topFiveSize();
	pcap_close(descr);
	fclose(f_Ethernet);
	fclose(f_Flujo);
	fclose(f_AnchoBanda);
	return OK;
}



void f_analizar_paquete(uint8_t *usuario, const struct pcap_pkthdr* cabecera,const uint8_t* paquete){
	int* contador=(int *)usuario;
	(*contador)++;
	char div_byte[2] = "0";
	char div_byte_2[10] = "0";
	uint16_t compare=0;
	long protocolo=0;
	int tam_E = 0;
	int ihl=0;
	int i=0;
	k++;/*Numero de paquetes*/

	printf("Nuevo paquete capturado el %s:",ctime((const time_t*)&(cabecera->ts.tv_sec)));

	if(token_des==1){
		printf("Direccion ETH destino= ");	
		printf("%02X",paquete[0]);
		for (i=1;i<ETH_ALEN;i++){
			printf(":%02X",paquete[i]);
		}
		printf("\n");
	}

	if ((token_ed==1) && (ed_filtro[0] != paquete[0] || ed_filtro[1] != paquete[1] || ed_filtro[2] != paquete[2]  || ed_filtro[3] != paquete[3] || ed_filtro[4] != paquete[4] || ed_filtro[5] != paquete[5])){
		printf("\nLa ETH Destino del paquete no coincide con la ETH Destino del filtro\n");
		return;
	}

	paquete+=ETH_ALEN;
	tam_E +=ETH_ALEN;
	
	if(token_des==1){
		printf("Direccion ETH origen = ");	
		printf("%02X",paquete[0]);
		for (i=1;i<ETH_ALEN;i++){
			printf(":%02X",paquete[i]);
		}
		printf("\n");
	}
	
	if ((token_eo==1) && (eo_filtro[0] != paquete[0] || eo_filtro[1] != paquete[1] || eo_filtro[2] != paquete[2]  || eo_filtro[3] != paquete[3] || eo_filtro[4] != paquete[4] || eo_filtro[5] != paquete[5])){
		printf("\nLa ETH Origen del paquete no coincide con la ETH Origen del filtro\n");
		return;
	}

	paquete+=ETH_ALEN;
	tam_E +=ETH_ALEN;
	compare = ntohs(*paquete);

	if(token_des==1){
		printf("TIpo ETH= ");	
		printf("0x%02X%02X",paquete[0], paquete[1]);
		printf("\n");	
	}	

	/*Comprobamos si el  tipo de Ethernet no es IP. Si no lo es finalizamos el programa*/
	if ( compare!=0x0800 && compare!=0x8100){
		printf("El tipo de Ethernet no es IP.\n");
		num_noip++;
		return;
	}

	paquete+=ETH_TLEN;
	tam_E +=ETH_TLEN;

	while( compare==0x8100){
		printf("El terminal tiene TAG VLAN.\n");
		num_vlan++;
		paquete+= VLAN_RES;
		tam_E +=VLAN_RES;
		compare = ntohs(*paquete);
		
		if (compare!=0x0800 && compare!=0x8100){
			printf("El tipo de Ethernet no es IP.\n");
			num_noip++;
			return;			
		}
		paquete += VLAN_TYPE;
		tam_E +=VLAN_TYPE;
	}
	
	num_ip++;
	
	sprintf(div_byte, "%02X", paquete[0]);
	
	if(token_des==1){
		printf("Version= ");	
		printf("%c", div_byte[0]);
		printf("\n");
	}

	div_byte[0] = '0';

	if(token_des==1){
		printf("IHL= ");	
		printf("%d", atoi(div_byte)*32/8);
		printf("\n");
	}

	ihl = atoi(div_byte)*32/8;
	ihl-=20;

	paquete+=IP_VERIHL;
	paquete+=IP_TIPOSERV;

    compare = htons(*(uint16_t *)paquete);

	if(token_des==1){
		printf("Longitud total= ");
		printf("%d", compare);
		printf("\n");
	}

	paquete+=IP_LONGTOT;
	paquete+=IP_IDENTIF;
	
	if(token_des==1){
		printf("Posicion (16 bits)= ");
		printf("%02X:%02X",paquete[0], paquete[1]);
		printf("\n");
	}

	paquete+=IP_POS;

	if(token_des==1){
		printf("Tiempo de vida= ");
		printf("%d", paquete[0]);
		printf("\n");
	}

	paquete+= IP_TVIDA;

	sprintf(div_byte_2 , "%d", paquete[0]);
	protocolo = atoi(div_byte_2);

	if(token_des==1){
		printf("Protocolo = ");	
		printf("%ld\n", protocolo);
	}

	if ((protocolo != 6) && (protocolo != 17)){
		printf("El protocolo no es ni TCP ni UDP.");
		num_others++;
		return;
	}

	paquete+= IP_PROT;
	paquete+=IP_SUMCAB;
	
	if(token_des==1){
		printf("Dir. IP Origen = ");
		printf("%d",paquete[0]);
		for (i=1;i<4;i++){
			printf(".%d",paquete[i]);
		}
		printf("\n");
	}

	if ((token_ipo==1) && (ipo_filtro[0] != paquete[0] || ipo_filtro[1] != paquete[1] || ipo_filtro[2] != paquete[2] || ipo_filtro[3] != paquete[3])){
		printf("\nLa IP Origen del paquete no coincide con la IP Origen del filtro\n");
		return;
	}

	paquete+= IP_DIR1;

	if(token_des==1){
		printf("Dir. IP Destino = ");
		printf("%d",paquete[0]);
		for (i=1;i<4;i++){
			printf(".%d",paquete[i]);
		}	
	}

	if ((token_ipd==1) && (ipd_filtro[0] != paquete[0] || ipd_filtro[1] != paquete[1] || ipd_filtro[2] != paquete[2] || ipd_filtro[3] != paquete[3])){
		printf("\nLa IP Destino del paquete no coincide con la IP Destino del filtro\n");
		return;
	}

	paquete+= IP_DIR2;
	if(ihl !=0)
		paquete+=ihl;

	if(token_des==1){
		printf("\n");
	}

	if (protocolo ==  6){

		if(token_des==1){
			printf("Los puertos del protocolo TCP son:\n");
			printf("Puerto origen= ");
			printf("%d", htons(*(uint16_t *)paquete));
			printf("\n");
		}

		add(htons(*(uint16_t *)paquete), cabecera->len);
		
		if((token_po == 1) && (po_filtro != htons(*(uint16_t *)paquete))){
			printf("\nEl puerto origen del paquete no coincide con el filtro\n");
			return;				
		}
			
		paquete+=TCP_PORIGEN;

		if(token_des==1){
			printf("Puerto destino= ");
			printf("%d", htons(*(uint16_t *)paquete));
			printf("\n");
		}

		add(htons(*(uint16_t *)paquete), cabecera->len);		
				
		if((token_pd == 1) && (pd_filtro != htons(*(uint16_t *)paquete))){
			printf("\nEl puerto destino del paquete no coincide con el filtro\n");
			return;				
		}				
				
		paquete+=TCP_PDEST;
		num_tcp++;
	}


	else if (protocolo == 17){ 

		if(token_des==1){
			printf("Los puertos del protocolo UDP y la longitud son:\n");
			printf("Puerto origen= ");
			printf("%d", htons(*(uint16_t *)paquete));
			printf("\n");	
		}

		add(htons(*(uint16_t *)paquete), cabecera->len);
				
		if((token_po == 1) && (po_filtro != htons(*(uint16_t *)paquete))){
			printf("\nEl puerto origen del paquete no coincide con el filtro\n");
			return;				
		}		
				
		paquete+=UDP_PORIGEN;

		if(token_des==1){
			printf("Puerto destino= ");
			printf("%d",  htons(*(uint16_t *)paquete));
			printf("\n");
		}

		add(htons(*(uint16_t *)paquete), cabecera->len);
		
		if((token_pd == 1) && (pd_filtro != htons(*(uint16_t *)paquete))){
			printf("\nEl puerto destino del paquete no coincide con el filtro\n");
			return;				
		}				
				
		paquete+=UDP_PDEST;

		if(token_des==1){
			printf("Longitud= ");
			printf("%d", htons(*(uint16_t *)paquete));
			printf("\n");
		}
				
		paquete+=UDP_LONG;
		num_udp++; 

	}
        
        /*Imprimir diferencias de tiempo en el que llegan los paquetes*/
        if(anterior_seg != 0){
            if(anterior_seg - cabecera->ts.tv_sec == 0)
                fprintf(f_Flujo, "%d\t%f\n", k, (float)(cabecera->ts.tv_usec - anterior_miliseg)/1000000.0);
            else if(anterior_miliseg > cabecera->ts.tv_usec)
                fprintf(f_Flujo, "%d\t%f\n", k, (float)(cabecera->ts.tv_sec - anterior_seg - 1.0) + (float)(1000000.0 - anterior_miliseg + cabecera->ts.tv_usec)/1000000.0);
            else
                fprintf(f_Flujo, "%d\t%f\n", k, (float)(cabecera->ts.tv_sec - anterior_seg) + (float)(cabecera->ts.tv_usec - anterior_miliseg)/1000000.0);
	}
        anterior_seg = cabecera->ts.tv_sec;
        anterior_miliseg = cabecera->ts.tv_usec;
        
        /*Imprimir tamaño de ethernet del paquete*/
	fprintf(f_Ethernet, "%d\t%d\n", k, (int)cabecera->len);
        
	/*Ancho de banda*/	
	if(segundo_seg == 0 && segundo_miliseg == 0){
		segundo_seg = cabecera->ts.tv_sec;
		segundo_miliseg = cabecera->ts.tv_usec;
		tam_acumulado += cabecera->len;
	}
	else if((((cabecera->ts.tv_usec - segundo_miliseg) > 0) && ((cabecera->ts.tv_sec - segundo_seg) == 1)) || ((cabecera->ts.tv_sec - segundo_seg) > 1)){
		tam_acumulado += cabecera->len;
		fprintf(f_AnchoBanda, "%d\t%ld\n", s, tam_acumulado);
		segundo_seg = 0;
		segundo_miliseg = 0;
		s++;
                tam_acumulado = 0;
	}else{
		tam_acumulado += cabecera->len;
	}

	printf("--------------------------------------\n");
}

