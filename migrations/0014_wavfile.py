# Generated by Django 5.0.3 on 2024-06-27 18:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('chat', '0013_alter_message_options_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='WavFile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('file', models.FileField(upload_to='wav_files/')),
            ],
        ),
    ]
