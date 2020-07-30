# OSCELOT DSKTOOL for HEROKU

NOTE: THIS PROJECT IS NOT PRODUCTION READY. FEEL FREE TO GIVE IT A SPIN AND HELP ME IMPROVE/FIX IT. :-)

THIS NOTICE WILL BE REMOVED WHEN THE PROJECT IS COMPLETE. (Thank you!)

This project is a Django/Python and Learn REST replacement for the Original York DSK Building Block for Learn.

It is built to be deployed on the Heroku. You may read about Heroku here: [https://heroku.com](https://heroku.com) 


If you want, this tool may be run on your desktop, on a remote server, or in the cloud on a PaaS of your choosing other than Heroku.

The DSKTOOL uses 3LO and as such requires a Learn account and use is restricted based on Learn account privileges (only Users with Admin accounts may post record updates).

Follow the below installation instructions.

**Note**: This is an open source community project and *is not supported or sponsored by Blackboard Inc.*. Pull requests welcome! Make a fork and share your work back to the project.

## Release Notes
### v1.0.4 (07/29/2020)
<ul>
  <li>Delete session cookie when Learn Logout link is used.</li>
  <li>Moved older release notes from app index page to here.</li>
</ul>

### v1.0.3 (07/29/2020)
<ul>
  <li>Heroku Deployable!</li>
  <li>3LO required on all pages</li>
</ul>

### v1.0.2 (07/28/2020)
<ul>
  <li>Heroku Enabled!(working out some DB details)</li>
  <li>3LO required on index load
  <li>strips spaces from around search terms
</ul>

### v1.0.1 (07/27/2020)
<ul>
  <li> Fixed django issues which were preventing correct loading </li>
  <li> Updated installation notes</li>
</ul>


### v1.0 (07/26/2020)
<ul>
  <li> Supports Data Source Key and Availability status for **single** User, Course, and Enrollment Records. </li>
  <li> Supports non-TLS (SSL) local python and Docker Desktop deployments
  <li> Supports TLS (SSL) deployments (see below TLS section)
</ul>

**ToDo:**
  <ul>
    <li>add search and update for multiple records</li>
    <li>add logging support</li>
    <li>analyze ditching Django for Flask</li>
    <li>add date timeboxing</li>
  </ul>
<hr>

# Installation

Prerequisiites:

You ***must*** have registered an application in your Developer Portal ([https://developer.blackboard.com](https://developer.blackboard.com)) account and added it to your Learn instance. 

NOTE: Make certain to store your Key and Secret as those will be required when you install the application.

### Learn
1. On your Learn instance create a user 'dsktooluser' and assign them a low, to no, privileged Institution role - I used "staff" - you may create a specific role if you choose. Do not assign a System Role. 
2. Navigate to the System Admin page and select the REST API Integrations link.
3. Enter your Application Id into the Application Id field.
2. Set the REST integration user to your 'dsktooluser'.
1. Set Available to 'Yes'.
1. Set End User Access to 'Yes'
1. Set Authorized To Act As User to 'Service Default'.
2. Click Submit.

Learn is now ready proceed with the installation by clickinng the below button:
(note as of 07/28 this will not work. Incomplete instructions: clone the project and use heroku cli to deploy... $ heroku create, dashboard to set env variables, then heroku push.)

<a href="https://heroku.com/deploy">
  <img src="https://www.herokucdn.com/deploy/button.svg" alt="Deploy">
</a>

