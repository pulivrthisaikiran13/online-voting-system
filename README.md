# Django-inventory-management

## Description
This system is built with Python (Django), JavaScript, Bootstrap, HTML, and CSS. The system offers a user-friendly front-end for general users and a secure back-end exclusively accessible to administrators. The back-end seamlessly retrieves and displays vital data from the database.

The system caters to two distinct user roles: administrators and staff members. Administrators have the privilege to log in and manage goods information, while staff members handle sales, purchases, bills, and invoice creation.

Powered sqlite3 database, our system not only stores all essential information but also boasts a user-friendly interface for effortless interaction. Users input data through this interface, and the system processes it, generating valuable insights based on user input. Additionally, the system diligently archives processed data in the database for future reference.

Project Setup Guide

# Step 1: Create a Virtual Environment
-------------------------------------

Navigate to your project directory (or create one if you haven't already):

CMD--->`cd  Django-inventory-management`


To create a virtual environment, run the following command:

For Windows:

CMD--->`python -m venv venv`

For macOS/Linux:

CMD--->`python3 -m venv venv`

# Step 2: Activate the Virtual Environment
---------------------------------------

After creating the virtual environment, activate it by running the appropriate command:

For Windows:

CMD--->`.\venv\Scripts\activate`

For macOS/Linux:

CMD--->`source venv/bin/activate`

# Step 3: Install Project Requirements
------------------------------------

Once the virtual environment is activated, you need to install the required dependencies.

> 3.1 Create a requirements.txt File (If Not Already Created)

If a requirements.txt file does not already exist in your project, you can create it manually or generate it by adding the necessary libraries.

Example of a basic requirement. txt file:

```python required libraries like
asgiref==3.5.2
certifi==2022.9.24
charset-normalizer==2.1.1
dj-database-url==1.0.0
Django==4.1.1
```

3.2 Install Dependencies

Once the requirements.txt file is ready, run the following command to install the dependencies:

CMD--->`pip install -r requirements.txt`

# Step 4: Run Django Project
----------------------------

4.1 Apply Migrations

Before running the server, apply any database migrations:

CMD--->`python manage.py migrate`

4.2 Create a Superuser (Optional)

To access the Django admin interface, create a superuser account:

CMD--->`python manage.py createsuperuser`

Enter the required details when prompted.

4.3 Run the Development Server

Start the Django development server:

RUN--->`python manage.py runserver`

Access the application at:

http://127.0.0.1:8000

# Step 5: (Optional)  without venv referring Use Docker for Project Setup
-----------------------------------------------------------------------
To using Docker without an .env file. You can achieve this by directly passing environment variables through the Docker CLI or defining them in your Dockerfile

Docker for Windows: https://www.docker.com/products/docker-desktop

Docker for macOS: https://www.docker.com/products/docker-desktop

Docker for Linux: https://docs.docker.com/get-docker
docker --version

