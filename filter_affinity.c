/*
 * Honors only allowed CPU affinity requests.
 * (C) 2013 Urban Borstnik under the GPLv3 license.
 * 
 * Based on ideas from the dustfairy library by
 * Adrian Ulrich.
 * 
 * The sched_setaffinity call is intercepted. The requested CPU
 * affinity is passed on the real call only if the request
 * respects the process's policy. Otherwise, the call returns
 * -1 and sets errno to EINVAL.
 *
 * If the AFFINITY_NO_COMPLAIN environment variable is set,
 * then an invalid requests are silently ignored and the
 * function returns a value of 0.
 *
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>

#include <errno.h>

#include <string.h>

#include <sched.h>
#include <unistd.h>

#include <dlfcn.h>

#define MAX_STR_LEN 256
#define DELIM ",\0"

struct bitmask {
        unsigned long size; /* number of bits in the map */
        unsigned long *maskp;
};

void get_logical_allowed_CPUs(int *logical_allowed)
{
        char *env_cpu_list;
        int ncpus = 0;

        /* Parse command delimited list for the environment variable, i.e.,
        * LSB_BIND_CPU_LIST=1,7,9 */
        if ((env_cpu_list = getenv("LSB_BIND_CPU_LIST")) != NULL) {
                size_t len;
                len = strlen(env_cpu_list);
                if(len) {
                        char buffer[len];
                        char *token;
                        int cpu;
                        const char delim[2] = DELIM;

                        if (strncpy(buffer, env_cpu_list, len) == NULL)
                                return 0;
                        token = buffer;
                        for (token = strtok(buffer, delim);
                                token != NULL;
                                token = strtok(NULL, delim)) {
                                        cpu = atoi(token);
                                        fprintf(stderr, "cpu #%d\n",cpu);
                                        logical_allowed[ncpus] = cpu;
                                        ncpus++;
                        }
                        return ncpus;
                }
        }

        return 0;
	
}

int get_allowed_CPUs(cpu_set_t *allowed) {
	char *env_cpu_list;
        int ncpus = 0;

	/* Parse command delimited list for the environment variable, i.e.,
         * LSB_BIND_CPU_LIST=1,7,9 */
	if ((env_cpu_list = getenv("LSB_BIND_CPU_LIST")) != NULL) {
		size_t len;
		len = strlen(env_cpu_list);
		if(len) {
			char buffer[len];
			char *token;
			int cpu;
			const char delim[2] = DELIM;

			if (strncpy(buffer, env_cpu_list, len) == NULL)
				return 0;
			CPU_ZERO(allowed);
			token = buffer;
			for (token = strtok(buffer, delim);
				token != NULL;
				token = strtok(NULL, delim)) {
					cpu = atoi(token);
				//	fprintf(stderr, "cpu #%d\n",cpu);
					CPU_SET(cpu, allowed);
					ncpus++;
			}
			return ncpus;
		}
	}

	return 0;
}

int have_full_node(int n_cpus) {
	char *alloc_str;
	char *my_host_name;
	char *loc;
	int len, a_cpus;

	if ((alloc_str = getenv("LSB_MCPU_HOSTS")) == NULL)
		return 0;
	if ((my_host_name = getenv("HOSTNAME")) == NULL)
		return 0;
	if ((loc = strstr(alloc_str, my_host_name)) == NULL)
		return 0;
	len = (int) strlen(loc);
	{
		char buffer[len];
		char *token;
		if (strncpy (buffer, loc, len) == NULL)
			return 0;
		token = strtok(buffer, " \0");
		token = strtok(NULL, " \0");
		a_cpus = atoi(token);
		fprintf(stderr, "Allocation of %d CPUs.\n", a_cpus);
		return (a_cpus == n_cpus);
	}
	return 0;
}

/* We intercept this call. */
int numa_sched_setaffinity(pid_t pid, struct bitmask *mask) {
	cpu_set_t requested_mask[CPU_SETSIZE], allowed_mask[CPU_SETSIZE], lnuma_mask[CPU_SETSIZE];
        static void * (*real_function)();

        int n_cpus;
        int allow_change;

        n_cpus = (int) sysconf(_SC_NPROCESSORS_CONF);
        fprintf(stderr, "There are %d CPUs.\n", n_cpus);
        /* Check whether the requested mask is allowed. */
        /* First gets the list of LSB-allocated CPUs. If it's empty, we */
        /* check if we are running exclusively on the node. */
        allow_change = 0;
        if (get_allowed_CPUs(allowed_mask)>0) {
                int bit;
                CPU_ZERO(lnuma_mask);
                for (bit = 0; bit < n_cpus; bit++)
                 if(((1L << bit) & *(mask->maskp)) != 0 )
                    	CPU_SET(bit,lnuma_mask);
                CPU_OR(requested_mask, lnuma_mask, allowed_mask); 
		allow_change = CPU_EQUAL(requested_mask, allowed_mask);
        } else {
                allow_change = have_full_node(n_cpus);
        }
        if (allow_change) {
                real_function = (void *(*) ()) dlsym(RTLD_NEXT, "sched_setaffinity");
                return (int) real_function(pid, sizeof(lnuma_mask),lnuma_mask);
        } else {
                char *env_var;
                if ((env_var = getenv("AFFINITY_NO_COMPLAIN")))
                        return 0;
		/*
 		* The requested mask does not match with LSF one, we give to numactl
 		* the mask defined by LSF
 		*/ 
		else{
			fprintf(stderr, "Using cores from cpuset.\n");
			real_function = (void *(*) ()) dlsym(RTLD_NEXT, "sched_setaffinity");
	                return (int) real_function(pid, sizeof(allowed_mask),allowed_mask);
		}
        }
}

/* We intercept this call. */
int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask) {
	cpu_set_t requested_mask[CPU_SETSIZE], allowed_mask[CPU_SETSIZE], used_mask[CPU_SETSIZE];
	static void * (*real_function)();

	int n_cpus,c_cpus;
	int allow_change;
	int *mapp_allowed_cpus,*l_allowed_mask;

	n_cpus = (int) sysconf(_SC_NPROCESSORS_CONF);
	fprintf(stderr, "There are %d CPUs.\n", n_cpus);
	/* Check whether the requested mask is allowed. */
	/* First gets the list of LSB-allocated CPUs. If it's empty, we
	 * check if we are running exclusively on the node. */
	allow_change = 0;
        c_cpus = get_allowed_CPUs(allowed_mask);
	CPU_ZERO(requested_mask);
	
	if (c_cpus > 0) {
		CPU_OR(requested_mask, mask, allowed_mask);
		allow_change = CPU_EQUAL(requested_mask, allowed_mask);
	} else {
		allow_change = have_full_node(n_cpus);
	}
	if (allow_change) {
		fprintf(stderr, "Change allowed.\n");
		real_function = (void *(*) ()) dlsym(RTLD_NEXT, "sched_setaffinity");
		return (int) real_function(pid, cpusetsize, mask);
	} else {
		char *env_var;
		if ((env_var = getenv("AFFINITY_NO_COMPLAIN")))
			return 0;
                /*
 		* The requested mask does not match with LSF one, we shuffle the 
 		* user mask	
 		* Algorithm to get the mapping - Urban Borstnik 
 		* 1. Let M(:) ← -1.
 		* 1. For each p in A, let M(p) ← p.
 		* 2. Let i←x|A(x)>|A| // I.e., find first entry in A that is greater than
 		* the requested core count. 
 		* 3. For each p in P where M(p)<0, do
 		*       let M(p) = A(i)
 		*             i = (i+1) % |A|
 		*/
                else{
			int p,greater,bit;

			fprintf(stderr, "Shuffling.\n");
			
			mapp_allowed_cpus = malloc(n_cpus*sizeof(int));
			memset (mapp_allowed_cpus, -1, n_cpus*sizeof (int) );
			l_allowed_mask = calloc(c_cpus,sizeof(int));			
	
			get_logical_allowed_CPUs(l_allowed_mask);

			greater = c_cpus;
			for(p=0; p < c_cpus; p++)
			{
				mapp_allowed_cpus[l_allowed_mask[p]] = l_allowed_mask[p];
				if(l_allowed_mask[p] > greater)
					greater = p;
			}
		 
		 		
			int index = greater;	
			for(p=0; p < n_cpus; p++)	
				if(mapp_allowed_cpus[p] == -1)
				{
					mapp_allowed_cpus[p] = l_allowed_mask[index]; 
					index = (index+1) % c_cpus;
				}

			CPU_ZERO(used_mask);
			for (bit=0;bit<n_cpus;bit++)
				if(CPU_ISSET(bit,mask)){
					CPU_SET(mapp_allowed_cpus[bit],used_mask);			
			}                                 


			free(mapp_allowed_cpus);
			free(l_allowed_mask);
                        real_function = (void *(*) ()) dlsym(RTLD_NEXT, "sched_setaffinity");
                        return (int) real_function(pid, sizeof(used_mask), used_mask);

                }
	}
}
