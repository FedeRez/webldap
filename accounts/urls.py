from django.conf.urls.defaults import patterns, include, url

urlpatterns = patterns('accounts.views',
    url(r'^$', 'profile'),
    url(r'^login/$', 'login'),
    url(r'^logout/$', 'logout'),
    url(r'^passwd/$', 'passwd'),
    url(r'^org/(?P<uid>[A-Za-z0-9-_]+)/$', 'org'),
    url(r'^org/(?P<uid>[A-Za-z0-9-_]+)/add/$', 'org_add'),
    url(r'^process/(?P<token>[a-z0-9]{32})/$', 'process'),
    url(r'^help/$', 'help'),
)
