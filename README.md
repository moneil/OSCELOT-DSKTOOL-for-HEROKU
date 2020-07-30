# OSCELOT DSKTOOL for HEROKU

This project is a Django/Python and Learn REST replacement for the Original York DSK Building Block for Learn.

This project is built to be deployed on the Heroku. You may read about Heroku here: [https://heroku.com](https://heroku.com) 

In order to meet the needs for a Heroku deployment there are some differences between this and the companion OSCELOT DSKTool project which supports python and containerized deployment. If those are of interest to you it is best to start with that project ([https://github.com/moneil/DSKTool](https://github.com/moneil/DSKTool)). Time and feasibility permiting I would like to merge these into a single project.

The DSKTOOL uses 3LO and as such requires a Learn account and use is restricted based on Learn account privileges.

**Note**: This is an open source community project and, even though I am an employee, *is not supported or sponsored by Blackboard Inc.*. If you find it of value please contribute! Pull requests welcome! Make a fork and share your work back to this project.

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

1. On your Learn instance create a user 'dsktooluser' and assign them a low, to no, privileged Institution role - I used "staff" - you may create a specific role if you choose. Do not assign a System Role. 
2. Navigate to the System Admin page and select the REST API Integrations link.
3. Enter your Application Id into the Application Id field
4. Set the REST integration user to your 'dsktooluser'.
5. Set Available to 'Yes'.
6. Set End User Access to 'Yes'
7. Set Authorized To Act As User to 'Service Default'.
8. Click Submit.

Learn is now ready and you may proceed with the installation by clicking the below button:

<a href="https://heroku.com/deploy">
  <img src="https://www.herokucdn.com/deploy/button.svg" alt="Deploy">
</a>
