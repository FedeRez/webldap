from django.conf.urls import patterns, url

urlpatterns = patterns(
    'main.views',
    url(r'^$', 'profile'),
    url(r'^edit/$', 'profile_edit'),
    url(r'^login/$', 'login'),
    url(r'^logout/$', 'logout'),
    url(r'^passwd/$', 'passwd'),
    url(r'^admin/$', 'admin'),
    url(r'^org/(?P<uid>[A-Za-z0-9-_]+)/$', 'org'),
    url(r'^org/(?P<uid>[A-Za-z0-9-_]+)/add/$', 'org_add'),
    url(r'^org/(?P<uid>[A-Za-z0-9-_]+)/promote/(?P<user_uid>[a-z-.]+)/$', 'org_promote'),
    url(r'^org/(?P<uid>[A-Za-z0-9-_]+)/relegate/(?P<user_uid>[a-z-.]+)/$', 'org_relegate'),
    url(r'^org/(?P<uid>[A-Za-z0-9-_]+)/enable_ssh/(?P<user_uid>[a-z-.]+)/$', 'enable_ssh'),
    url(r'^org/(?P<uid>[A-Za-z0-9-_]+)/disable_ssh/(?P<user_uid>[a-z-.]+)/$', 'disable_ssh'),
    url(r'^org/(?P<uid>[A-Za-z0-9-_]+)/enable_admin/(?P<user_uid>[a-z-.]+)/$', 'enable_admin'),
    url(r'^org/(?P<uid>[A-Za-z0-9-_]+)/disable_admin/(?P<user_uid>[a-z-.]+)/$', 'disable_admin'),
    url(r'^process/(?P<token>[a-z0-9]{32})/$', 'process'),
    url(r'^help/$', 'help'),
)
