# Generated by Django 3.1.1 on 2020-09-03 11:33

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('observes', '0002_auto_20200903_1131'),
    ]

    operations = [
        migrations.AlterField(
            model_name='scan',
            name='scan_date',
            field=models.DateTimeField(blank=True, null=True, verbose_name='scan date'),
        ),
    ]
