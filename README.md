FedeRez LDAP web interface
==========================

**webLDAP** gives users access to their LDAP accounts and eases the management
of such accounts by organization managers and administrators.

Technology
----------

Views rely on **ldapom** to issue LDAP requests. This library is built upon
the python-ldap module.

South is used for database migrations.

This project differs quite a lot from usual Django projects because of the lack
of ORM-style managers for LDAP. That's why the authentication backend and many
useful Django modules are not used.

Architecture
------------

This Django project is meant to be simple. One app `main` inside the `webldap` project.

Main files:

    webldap/
        settings.py: project settings
        local_settings.sample.py: sample settings to be completed and renamed
    main/
        views.py: view functions (no class-based views)
        migrations: South migrations
        static/: static content

Install
-------

See `requirements.txt` for what needs to be installed first.

* Edit `local_settings.sample.py` and save it as `local_settings.py`.
* Create database:

        python manage.py syncdb
        python manage.py migrate main

* Configure your web server or just run `python manage.py runserver`

And you're set!

Using and contributing
----------------------

webldap is licensed under the MIT license. For more information, see the
`LICENSE` file.

You are welcome to contribute to this project, preferably by pull requests or
email.
