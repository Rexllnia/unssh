/*
 * Dropbear SSH
 * 
 * Copyright (c) 2002,2003 Matt Johnston
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */

#include "includes.h"
#include "buffer.h"
#include "dbutil.h"
#include "session.h"
#include "ssh.h"
#include "runopts.h"
#include "json-c/json.h"
#include <stdarg.h>

char g_password[1024];
int g_host_is_exit;
#if DROPBEAR_CLI_PASSWORD_AUTH

#if DROPBEAR_CLI_ASKPASS_HELPER
/* Returns 1 if we want to use the askpass program, 0 otherwise */
static int want_askpass()
{
	char* askpass_prog = NULL;

	askpass_prog = getenv("SSH_ASKPASS");
	return askpass_prog && 
		((!isatty(STDIN_FILENO) && getenv("DISPLAY") )
		 	|| getenv("SSH_ASKPASS_ALWAYS"));
}

/* returns a statically allocated password from a helper app, or NULL
 * on failure */
static char *gui_getpass(const char *prompt) {

	pid_t pid;
	int p[2], maxlen, len, status;
	static char buf[DROPBEAR_MAX_CLI_PASS + 1];
	char* helper = NULL;

	TRACE(("enter gui_getpass"))

	helper = getenv("SSH_ASKPASS");
	if (!helper)
	{
		TRACE(("leave gui_getpass: no askpass program"))
		return NULL;
	}

	if (pipe(p) < 0) {
		TRACE(("error creating child pipe"))
		return NULL;
	}

	pid = fork();

	if (pid < 0) {
		TRACE(("fork error"))
		return NULL;
	}

	if (!pid) {
		/* child */
		close(p[0]);
		if (dup2(p[1], STDOUT_FILENO) < 0) {
			TRACE(("error redirecting stdout"))
			exit(1);
		}
		close(p[1]);
		execlp(helper, helper, prompt, (char *)0);
		TRACE(("execlp error"))
		exit(1);
	}

	close(p[1]);
	maxlen = sizeof(buf);
	while (maxlen > 0) {
		len = read(p[0], buf + sizeof(buf) - maxlen, maxlen);
		if (len > 0) {
			maxlen -= len;
		} else {
			if (errno != EINTR)
				break;
		}
	}

	close(p[0]);

	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return(NULL);

	len = sizeof(buf) - maxlen;
	buf[len] = '\0';
	if (len > 0 && buf[len - 1] == '\n')
		buf[len - 1] = '\0';

	TRACE(("leave gui_getpass"))
	return(buf);
}
#endif /* DROPBEAR_CLI_ASKPASS_HELPER */

#define HOST_INFO_PATH "/etc/unsecure-ssh/host_info"
int unssh_update_host_info(cli_runopts *cli_opts,char *password)
{
	int fd,i,len;
	char buf[100];
	json_object *root,*host_array,*host_object,*username_obj,*remotehost_obj,*password_obj;

	if (password == NULL || cli_opts == NULL) {
		return -1;
	}
	len = 0;
	if (access(HOST_INFO_PATH,F_OK) == -1) {
		fd = creat(HOST_INFO_PATH,0777);
		if (fd < 0) {
			return -1;
		}
		close(fd);
	}
	root = json_object_from_file(HOST_INFO_PATH);
	if (root == NULL) {
		return -1;
	}	
	host_array = json_object_object_get(root,"host");
	if (host_array == NULL) {
		return -1;
	}
	DEBUG1(("1"));
	for (i = 0;i < json_object_array_length(host_array);i++) {
		host_object = json_object_array_get_idx(host_array,i);
		username_obj = json_object_object_get(host_object,"username");
		remotehost_obj = json_object_object_get(host_object,"remotehost");
		password_obj = json_object_object_get(host_object,"password");
		if (strcmp(cli_opts->username,json_object_get_string(username_obj)) == 0) {
			if (strcmp(cli_opts->remotehost,json_object_get_string(remotehost_obj)) == 0) {
				DEBUG1(("2"));
				json_object_object_add(host_object,"password",json_object_new_string(password));
				DEBUG1(("3"));
				json_object_to_file(HOST_INFO_PATH,root);

				json_object_put(root);
				return 0;
			}
		}

	}
	// json_object_put(host_array);
	json_object_put(root);
	return -1;
}

int unssh_del_host_info(cli_runopts *cli_opts)
{
	int fd,i,len;
	char buf[100];
	json_object *root,*host_array,*host_object,*username_obj,*remotehost_obj,*password_obj;

	len = 0;
	if (access(HOST_INFO_PATH,F_OK) == -1) {
		fd = creat(HOST_INFO_PATH,0777);
		if (fd < 0) {
			return -1;
		}
		close(fd);
	}
	root = json_object_from_file(HOST_INFO_PATH);
	if (root == NULL) {
		return -1;
	}	
	host_array = json_object_object_get(root,"host");
	if (host_array == NULL) {
		return -1;
	}

	for (i = 0;i < json_object_array_length(host_array);i++) {
		host_object = json_object_array_get_idx(host_array,i);
		username_obj = json_object_object_get(host_object,"username");
		remotehost_obj = json_object_object_get(host_object,"remotehost");
		if (strcmp(cli_opts->username,json_object_get_string(username_obj)) == 0) {
			if (strcmp(cli_opts->remotehost,json_object_get_string(remotehost_obj)) == 0) {
				json_object_array_del_idx(host_array,i,1);
				json_object_to_file(HOST_INFO_PATH,root);

				// json_object_put(host_array);
				json_object_put(root);
				return 0;
			}
		}

	}
	// json_object_put(host_array);
	json_object_put(root);
	return -1;
}

int unssh_read_host_info(cli_runopts *cli_opts,char **password)
{
		int fd,i,len;
		char buf[100];
		json_object *root,*host_array,*host_object,*username_obj,*remotehost_obj,*password_obj;

		len = 0;
		if (access(HOST_INFO_PATH,F_OK) == -1) {
			fd = creat(HOST_INFO_PATH,0777);
			if (fd < 0) {
				return -1;
			}
			close(fd);
		}
		root = json_object_from_file(HOST_INFO_PATH);
		if (root == NULL) {
			return -1;
		}	
		host_array = json_object_object_get(root,"host");
		if (host_array == NULL) {
			return -1;
		}

    	for (i = 0;i < json_object_array_length(host_array);i++) {
        	host_object = json_object_array_get_idx(host_array,i);
			username_obj = json_object_object_get(host_object,"username");
			remotehost_obj = json_object_object_get(host_object,"remotehost");
			password_obj = json_object_object_get(host_object,"password");
			if (strcmp(cli_opts->username,json_object_get_string(username_obj)) == 0) {
				if (strcmp(cli_opts->remotehost,json_object_get_string(remotehost_obj)) == 0) {
					len = json_object_get_string_len(password_obj) + 1;
					*password = (char *)malloc(len);

				
					// sprintf(buf,"echo %s >>/home/zhengyufan/dropbear-DROPBEAR_2022.83/mylog",json_object_get_string(password_obj));
					// system(buf);
					
					strncpy(*password,json_object_get_string(password_obj),len);
					// printf("password %s\r\n",password);

					// sprintf(buf,"echo %s >>/home/zhengyufan/dropbear-DROPBEAR_2022.83/mylog",*password);
					// system(buf);
					// json_object_put(host_array);
					json_object_put(root);	
					DEBUG1(("found"))
					return 0;
				}
			}

		}
		// json_object_put(host_array);
		json_object_put(root);	
		DEBUG1(("not found"))
		return -1;
}
int unssh_write_host_info(cli_runopts *cli_opts,char *password)
{
		int fd;
		json_object *root,*host_array,*host_object;

		if (password == NULL) {
			return -1;
		}

		if (access(HOST_INFO_PATH,F_OK) == -1) {
			fd = creat(HOST_INFO_PATH,0777);
			if (fd < 0) {
				return -1;
			}
			close(fd);
		}
		root = json_object_from_file(HOST_INFO_PATH);
		if (root == NULL) {
			root = json_object_new_object();
		}
		DEBUG1(("1"))
		DEBUG1(("2"))
		
		// char buf[100];
		host_array = json_object_object_get(root,"host");
		if (host_array == NULL) {
			host_array = json_object_new_array();
			json_object_object_add(root,"host",host_array);
		}
		host_object = json_object_new_object();
		DEBUG1(("3"))
		json_object_object_add(host_object,"username",json_object_new_string(cli_opts->username));
		DEBUG1(("4"))
		json_object_object_add(host_object,"remotehost",json_object_new_string(cli_opts->remotehost));
		DEBUG1(("5"))
		json_object_object_add(host_object,"password",json_object_new_string(password));
		DEBUG1(("6"))
		json_object_array_add(host_array,host_object);
		// json_object_object_add(root,"host",host_array);
		json_object_to_file(HOST_INFO_PATH,root);
		// sprintf(buf,"echo %s >>/home/zhengyufan/dropbear-DROPBEAR_2022.83/mylog",password);
		// system(buf);
		json_object_put(host_object);
		json_object_put(host_array);
		json_object_put(root);	
		return 0;
}
void cli_auth_password() {

	char* password = NULL;
	char prompt[80];
	static int retry;

	DEBUG1(("enter cli_auth_password"))
	CHECKCLEARTOWRITE();

	snprintf(prompt, sizeof(prompt), "%s@%s's pass123word: ", 
				cli_opts.username, cli_opts.remotehost);
#if DROPBEAR_CLI_ASKPASS_HELPER
	if (want_askpass())
	{
		password = gui_getpass(prompt);
		if (!password) {
			dropbear_exit("No password");
		}
	} else
#endif
	{
		retry++;
		DEBUG1(("retry %d",retry))

		if ((unssh_read_host_info(&cli_opts,&password) == -1 ) || (retry > 1)) {
			password = getpass_or_cancel(prompt);
			g_host_is_exit = 0;

		} else {
			g_host_is_exit = 1;
		}
		DEBUG1(("%s",password))
		strcpy(g_password,password);
	}
	buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_REQUEST);

	buf_putstring(ses.writepayload, cli_opts.username,
			strlen(cli_opts.username));

	buf_putstring(ses.writepayload, SSH_SERVICE_CONNECTION,
			SSH_SERVICE_CONNECTION_LEN);

	buf_putstring(ses.writepayload, AUTH_METHOD_PASSWORD,
			AUTH_METHOD_PASSWORD_LEN);

	buf_putbyte(ses.writepayload, 0); /* FALSE - so says the spec */
	buf_putstring(ses.writepayload, password, strlen(password));
	encrypt_packet();
	m_burn(password, strlen(password));
	cli_ses.is_trivial_auth = 0;
	TRACE(("leave cli_auth_password"))
}
#endif	/* DROPBEAR_CLI_PASSWORD_AUTH */
