# Generated by Django 2.1.7 on 2019-04-11 08:30

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rest_framework_api_key', '0004_auto_20180924_1303'),
    ]

    operations = [
        migrations.CreateModel(
            name='Scope',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=64, unique=True)),
                ('description', models.TextField(blank=True, null=True)),
            ],
        ),
        migrations.AddField(
            model_name='apikey',
            name='scopes',
            field=models.ManyToManyField(blank=True, help_text='A list of service scope for this api key.', related_name='keys', to='rest_framework_api_key.Scope'),
        ),
    ]
