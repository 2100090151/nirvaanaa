# Generated by Django 3.2 on 2023-05-12 15:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('listings', '0002_contact'),
    ]

    operations = [
        migrations.AlterField(
            model_name='listing',
            name='id',
            field=models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID'),
        ),
    ]
