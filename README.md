# Pet Travel Hub

A microblog with Python Flask framework that allows users to register and share content, providing a platform for pet travel enthusiasts.

## Technology: Python Flask, HTML, CSS

### Functionality 

From the landing page, user can register/login to access the rest of the site. User credentials are stored in a text file. Once user completes registration, the site validates the credentials against the file and redirects to the login page.

### Feedback

Flask flashing system is utilized to display on-screen messages to inform the user if registration and other operations were completed successfully.

### Security

User is required to login to access content. Flask @login_required is implemented. Password security is implemented requiring at least 12 character password length. User is notified if the requirement is not met. The passwords are also checked against common password list.

### Visit the site 

https://jellyfish-app-edwjy.ondigitalocean.app
