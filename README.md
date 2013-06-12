FedeRez LDAP web interface
==========================

**webLDAP** gives users access to their LDAP accounts and eases the management
of such accounts by organization managers and administrators.

Technology
----------

Views rely on `libldap.py` to issue LDAP requests. This library is built upon
the python-ldap module.

South is used for database migrations.

This project differs quite a lot from usual Django projects because of the lack
of ORM-style managers for LDAP. That's why the authentication backend and many
useful Django modules are not used.

Architecture
------------

This Django project is meant to be simple. One app `accounts` inside the
`federez_ldap` project.

Main files:

    federez_ldap/
        settings.py: project settings
        settings_local.sample.py: sample settings to be completed and renamed
    accounts/
        libldap.py: LDAP helpers
        views.py: view functions (no class-based views)
        migrations: South migrations
        static/: static content

Install
-------

See `requirements.txt` for what needs to be installed first.

* Edit `settings_local_sample.py` and save it as `settings_local.py`.
* Create database:

        python manage.py syncdb
        python manage.py migrate accounts

* Configure your web server or just run `python manage.py runserver`

And you're set!
