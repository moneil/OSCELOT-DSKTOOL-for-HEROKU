# OSCELOT DSKTOOL for HEROKU v1.0.8 09.25.2020

See below [Release Notes](#Release-Notes).

This project is a Django/Python and Learn REST replacement for the Original York DSK Building Block for Learn.

This project is built to be deployed on the Heroku. You may read about Heroku here: [https://heroku.com](https://heroku.com) 

In order to meet the needs for a Heroku deployment there are some differences between this and the companion OSCELOT DSKTool project which supports python and containerized deployment. If those are of interest to you it is best to start with that project ([https://github.com/moneil/DSKTool](https://github.com/moneil/DSKTool)). I have begun the process of merging these projects. See the 'docker' and 'local' folders in the repository for installation and usage instructions.

The DSKTOOL uses 3LO and as such requires a Learn account and use is restricted based on Learn account privileges.

**Note**: This is an open source community project and, even though I am an employee, *is not supported or sponsored by Blackboard Inc.*. If you find it of value please contribute! Pull requests welcome! Make a fork and share your work back to this project.

# Installation

## Pre-requisites:
You ***must*** have registered an application in your Developer Portal ([https://developer.blackboard.com](https://developer.blackboard.com)) account and added it to your Learn instance. 

NOTE: Make certain to store your Key and Secret as those will be required when you install the application.

## Blackboard Learn
1. On your Learn instance create a user 'dsktooluser' and assign them a low, to no, privileged Institution role - I used "staff" - you may create a specific role if you choose. Do not assign a System Role. 
2. Navigate to the System Admin page and select the REST API Integrations link.
3. Enter your Application Id into the Application Id field
4. Set the REST integration user to your 'dsktooluser'.
5. Set Available to 'Yes'.
6. Set End User Access to 'Yes'
7. Set Authorized To Act As User to 'Service Default'.
8. Click Submit.

Learn is now ready and you may proceed with the installation by clicking the below button and following the instuctions.

## Heroku

Clicking the below 'Deploy to Heroku' button will open Heroku to your application setup screen. 

Note: if you do not have a Heroku account you will be prompted to create one. You will be directed to the setup screen on account create completion.

<a href="https://heroku.com/deploy">
  <img src="https://www.herokucdn.com/deploy/button.svg" alt="Deploy">
</a>

### Configuring your application
On the setup screen you will need to name your application dyno, select a region and set the configuration variables:
 
1. Enter an application name - Heroku will let you know if it is valid. e.g. PostDSKTOOL.
2. Choose a region that applies or is closest to you.
3. Set the required **APPLICATION\_KEY** config variable using the APPLICATION KEY provided when you registered your Application in the Blackboard Developer Portal. (Contains hyphens)
4. Set the required **APPLICATION\_SECRET** config variable using the APPLICATION SECRET provided when you registered your Application. (Contains no hyphens)
5. Set the **BLACKBOARD\_LEARN\_INSTANCE** config variable to the FQDN for your target Blackboard Learn instance. E.g.: demo.blackboard.com. DO NOT include the protocol (http:// or https://)
6. Leave the required **DISABLE\_COLLECTSTATIC** config variable set to the current setting of 1 - this is required for a successful deploy.
7. Set the required **DJANGO\_SECRET\_KEY** config variable using the DJANGO SECRET gennerated from this website: https://djskgen.herokuapp.com NOTE: remove the single quotes e.g.: 
`=)**)-eozw)jt@hh!lkdc3k-h$gty+12sv)i(r8lp6rn9yn9w&` 
**NOT** 
`'=)**)-eozw)jt@hh!lkdc3k-h$gty+12sv)i(r8lp6rn9yn9w&'`
Retaining the single quotes will cause the install to fail.

After entering the above click the '**Deploy app**' button at the bottom of the page. 

This starts the deployment and on successful completion you will see a message at the bottom of the page '**Your app was successfully deployed.**' along with two buttons, one for Managing your app and one to View - click '**View**' button to open your app in your browser. 

This URL is sticky so bookmark it for later use and you are done!

**IMPORTANT:** After significant testing I have found that the 3LO redirect to login, which this tool uses, does not work if you are using Direct Portal Entry (where your login is on the community/institution landing page). I believe v1.0.5 mediates this issue.

**Work Around:** login to your Learn instance before opening your dsktool page.

## Release Notes
### v1.0.8 (09/25/2020)
This release focuses on improving the user experience for searching and updating Enrollments:
<ul>
  <li>Enrollments: Added Course/Org and User membership searches and updating to Enrollments
  <li>Enrollments: Course/Org and User membership searches support externalId and courseId/Username
  <li>Enrollments: Improved UI using AJAX
  <li>Enrollments: Added alerts for entry validation and errors
  <li>Enrollments: Substantial logging to Javascript console for debugging
</ul>

**ToDo:**
  <ul>
    <li>Change User and Course searches to ajax with improved UI and error checking
    <li>Continue support for single project for multiple deployment models (Heroku, Desktop, or Docker). Current code fully supports Heroku and local use. Use the above deploy button or follow the instructions in the local folder. Docker coming soon.
    <li>add logging support</li>
    <li>analyze ditching Django for Flask</li>
    <li>add date timeboxing</li>
  </ul>

### v1.0.5 (08/16/2020)
<ul>
  <li>Begin support for single project for multiple deployment models (Heroku, Desktop, or Docker). Current code fully supports Heroku and local use. Use the above deploy button or follow the instructions in the local folder. Docker coming soon.</li>
  <li>Added 3LO handling for guest user results when target Learn instances use SSO or Direct Entry.</li>
  <li>Added 3LO and 500 error trapping.</li>
</ul>

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
<hr>
