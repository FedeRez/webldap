from django.conf.urls.defaults import patterns, include, url

urlpatterns = patterns('accounts.views',
    url(r'^login/$', 'login'),
    url(r'^profile/$', 'profile'),
    url(r'^test/$', 'test'),
)
