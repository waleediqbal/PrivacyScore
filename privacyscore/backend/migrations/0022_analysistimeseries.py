# -*- coding: utf-8 -*-
# Generated by Django 1.11.10 on 2018-03-19 16:26
from __future__ import unicode_literals

import django.contrib.postgres.fields.jsonb
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0021_auto_20171215_0039'),
    ]

    operations = [
        migrations.CreateModel(
            name='AnalysisTimeSeries',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('result', django.contrib.postgres.fields.jsonb.JSONField(blank=True, null=True)),
                ('analysis', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='time_data', to='backend.Analysis')),
            ],
        ),
    ]
