# -*- coding: utf-8 -*-
# Generated by Django 1.11.6 on 2017-12-14 23:42
from __future__ import unicode_literals

import django.contrib.postgres.fields.jsonb
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0019_analysis'),
    ]

    operations = [
        migrations.CreateModel(
            name='AnalysisCategory',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('result', django.contrib.postgres.fields.jsonb.JSONField(blank=True, null=True)),
                ('analysis', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='category', to='backend.Analysis')),
            ],
        ),
    ]
