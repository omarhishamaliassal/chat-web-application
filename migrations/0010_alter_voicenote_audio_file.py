# Generated by Django 5.0.3 on 2024-05-08 16:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('chat', '0009_message_audio_file_alter_message_body'),
    ]

    operations = [
        migrations.AlterField(
            model_name='voicenote',
            name='audio_file',
            field=models.BinaryField(blank=True, null=True),
        ),
    ]
