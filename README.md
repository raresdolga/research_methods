# Privacy in Governmental Services
#### Description
Virtual Box IP: 127.0.0.1

##### Issuer app Asdmin
- super-user: issuer_admin
- password: issuer_10
- email: rares.dolga.16@ucl.ac.uk
##### User app Admin
- super-user : usr_admin
- password: usr_10
- email: rares.dolga.16@ucl.ac.uk
#### Configure Apache with django
[Django + Apache config Link]( https://www.digitalocean.com/community/tutorials/how-to-serve-django-applications-with-apache-and-mod_wsgi-on-ubuntu-16-04)

- 000-default.conf = content Config file for Apache made for projects. Contents of this file must be copied in:
-      /etc/apache2/sites-available/000-default.conf
- Do not forget to give necessary permissions for Apache to read/write in project files and db. Follow the tutorial for this.

#### Projects configuration
Make a virtual environment for each project (1 issuer, 1 user) - Otherwise Apache won't work.

#### Apache with  https:
1. Generate a local certificate(bellow tutorial)
2. Configure your default-ssl.conf with code from default-ssl.conf in this repo. Change your path structure as needed. 
3. The HTTPS will run on port 443.
4. The 80 port (default) is configure to redirect to 443
[Tutorial Link](https://www.digitalocean.com/community/tutorials/how-to-create-a-ssl-certificate-on-apache-for-ubuntu-14-04)

#### Asynchronous responses:       
Use celery to send a response in async. Send an email to the user when the credential is ready to be used.      
https://medium.com/@ffreitasalves/executing-time-consuming-tasks-asynchronously-with-django-and-celery-8578eebab356





