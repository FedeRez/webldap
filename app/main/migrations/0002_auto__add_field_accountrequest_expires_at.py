# -*- coding: utf-8 -*-
import datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding field 'AccountRequest.expires_at'
        db.add_column('main_accountrequest', 'expires_at',
                      self.gf('django.db.models.fields.DateTimeField')(default=datetime.datetime(2013, 4, 5, 0, 0)),
                      keep_default=False)


    def backwards(self, orm):
        # Deleting field 'AccountRequest.expires_at'
        db.delete_column('main_accountrequest', 'expires_at')


    models = {
        'main.accountrequest': {
            'Meta': {'object_name': 'AccountRequest'},
            'created_at': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '254'}),
            'expires_at': ('django.db.models.fields.DateTimeField', [], {}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '200'}),
            'org_uid': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'token': ('django.db.models.fields.CharField', [], {'max_length': '32'}),
            'uid': ('django.db.models.fields.CharField', [], {'max_length': '200'})
        }
    }

    complete_apps = ['main']
