 /***********************************************************
 crearCDF.c	 
 Primeros pasos para implementar y validar la funcion crearCDF(). Est funcion debe devolver
 un fichero con dos columnas, la primera las muestras, la segunda de distribucion de
 probabilidad acumulada. En la version actual la funcion realiza los dos primeros pasos para
 este objetivo, cuenta el numero de muestras y las ordena.
 El alumno debe acabar su implementacion de crearCDF() y usar un main similar para validar su fucionamiento.
 
 Compila: gcc -Wall -o crearCDF crearCDF.c
 Autor: Jose Luis Garcia Dorado
 2014 EPS-UAM 
***************************************************************************/

#include <stdio.h> 
#include <stdlib.h> 
#include <strings.h> 
#include <string.h> 

#define OK 0
#define ERROR 1

typedef struct{
   float id;
   float value;
}Estadistica;

typedef struct{
   int id;
   float value;
}Estructura;

Estadistica* estadistica=NULL; 
Estructura *leido = NULL;

int e=0;
int num_elem=0;

void prepSalida(){
	int i, j;	
	for(i=0;i<e;i++){
		for(j=0;j<num_elem;j++)
			if(leido[j].value == estadistica[i].id)
				leido[j].value = estadistica[i].value;
	}
}

void ECDF(){
    int i, j;
    for(i=e-1;i>=0;i--){
		for(j=0;j<i;j++)
			estadistica[i].value += estadistica[j].value;
	}
}

void makeProb(int num){
	int i;
	for(i=0; i < e; i++)
		estadistica[i].value = (float)estadistica[i].value/(float)num;
}

void sortEstadistica(){
    int i=0, t=e, num=0;
        float aux_value = 0, aux_id=0;
	for(;num<e;num++){
		for(i=0;i<t-1;i++){
			if(estadistica[i].id > estadistica[i+1].id){
				aux_id = estadistica[i].id;
				aux_value = estadistica[i].value;
				estadistica[i].id = estadistica[i+1].id;
				estadistica[i].value = estadistica[i+1].value;
				estadistica[i+1].id = aux_id;
				estadistica[i+1].value = aux_value;
			}
		}
		t=t-1;
	}
    
}

void addEstadistica(float id){	
	int flag = 0;
	int i;
	
	if(e==0 && estadistica == NULL){
		estadistica = (Estadistica*)malloc(sizeof(Estadistica));
		estadistica[0].id = id;
		estadistica[0].value = 1;
		e++;
	}
	else{
		for(i=0; i < e; i++)
			if (estadistica[i].id == id){
				estadistica[i].value++;
				flag=1;
			}
		if (flag==0){
			estadistica=(Estadistica*)realloc(estadistica ,(e+1) * sizeof(Estadistica));
			estadistica[e].id = id;
			estadistica[e].value++;
			e++;
		}
	}
}

int crearCDF(char* filename_data, char* filename_cdf);

int main(int argc, char **argv){
	if(argc < 3)
		crearCDF(argv[1],"salida.txt");
	return OK;
}

int crearCDF(char* filename_data, char* filename_cdf) {
	char comando[255]; char linea[255]; char aux[255]; char titulo[255];
	int num_lines;
	FILE *f_in, *f_out, *f;
	int i;

	sprintf(comando,"wc -l %s 2>&1",filename_data); //wc cuenta lineas acabadas por /n
	printf("Comando en ejecucion: %s\n",comando);
	f = popen(comando, "r");
	if(f == NULL){
		printf("Error ejecutando el comando\n");
		return ERROR;
	}
	fgets(linea,255,f);
	printf("Retorno: %s\n",linea);
	sscanf(linea,"%d %s",&num_lines,aux);
	num_elem = atoi(linea) - 1;
	pclose(f);

	sprintf(comando,"sort -n < %s > %s 2>&1",filename_data,filename_cdf);
	printf("Comando en ejecucion: %s\n",comando);
	f = popen(comando, "r");
	if(f == NULL){
		printf("Error ejecutando el comando\n");
		return ERROR;
	}
	bzero(linea,255);
	fgets(linea,255,f);
	printf("Retorno: %s\n",linea);
	pclose(f);

	f_in = fopen("salida.txt", "r");
	
	fscanf(f_in, "%s\t%[^\n]", titulo, titulo);
	
	printf("%s\n", titulo);	

	leido = (Estructura*)malloc(num_elem*sizeof(Estructura));

	printf("%d\n", num_elem);

	/*Leemos elementos y acumulamos para despues hacer la probabilidad*/
	for(i=0;i<num_elem;i++){
		fscanf(f_in, "%d\t%f\n", &leido[i].id ,&leido[i].value);
		//printf("%d\t%f\n", leido[i].id, leido[i].value);
		addEstadistica(leido[i].value);
	}

	fclose(f_in);
	
	f_out = fopen("salida.txt", "w");	

	fprintf(f_out, "%s\t%s\n", "N.", "Probabilidad");

	makeProb(num_elem);
	
	//prepSalida();
        
    sortEstadistica();
    
    ECDF();

	/*Escribimos resultados en nuevo fichero*/
	for(i=0;i<e;i++){
		fprintf(f_out, "%f\t%f\n", estadistica[i].id ,estadistica[i].value);
	}

	return OK;
}

