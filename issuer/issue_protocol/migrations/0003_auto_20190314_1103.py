# Generated by Django 2.1.7 on 2019-03-14 11:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('issue_protocol', '0002_auto_20190314_1055'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='credential_batch',
            name='id',
        ),
        migrations.AlterField(
            model_name='credential_batch',
            name='user_name',
            field=models.CharField(max_length=120, primary_key=True, serialize=False),
        ),
    ]
