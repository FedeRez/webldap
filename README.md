FedeRez LDAP web interface
==========================

**webLDAP** enables users to access their LDAP accounts and eases the management of such
accounts by administrators.

Architecture
------------

The project is called `webldap` and the only application in it is `main`.

Main files:

    webldap/
        settings.py: project settings
        local_settings.sample.py: sample settings
        local_settings.docker.py: Docker-specific settings
    main/
        views.py: view functions (no class-based views)
        static/: static content

Install
-------

### Normal

See `app/requirements.txt` for what needs to be installed first.

* In `app/webldap`, copy `local_settings.sample.py` to `local_settings.py` and edit the
  latter with your settings.
* Create the database:

        python manage.py migrate

* Configure your web server, or just run `python manage.py runserver` if you are
  testing the software.

### Docker (development only)

You need both [Docker](https://www.docker.com) and
[docker-compose](https://docs.docker.com/compose/).  It is recommended you get familiar
with Docker before using it for this project.

* Copy `secret.sample.yml` to `secret.yml` and edit it with the password you want to use.
* In `app/webldap`, copy `local_settings.docker.py` to `local_settings.py` and edit the
  secret key and the password.
* To initialize the LDAP database and start the server, run:

        docker-compose run ldap /usr/bin/slapd-init
        docker-compose up

  It should then be running on `http://localhost:8000`.

To take modifications into account:

```
docker-compose rm -f
docker-compose build
docker-compose up
```

To reset the LDAP database:

```
docker-compose rm -f
docker-compose run ldap /usr/bin/slapd-init
docker-compose up
```

If slapd crashes when it starts, try to raise the available RAM on your development
machine to at least 1&nbsp;Gio.

Using and contributing
----------------------

webldap is licensed under the MIT license. For more information, see the `LICENSE` file.

You are welcome to contribute to this project, preferably by pull requests or email.
