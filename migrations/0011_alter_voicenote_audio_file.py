# Generated by Django 5.0.3 on 2024-05-08 20:30

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('chat', '0010_alter_voicenote_audio_file'),
    ]

    operations = [
        migrations.AlterField(
            model_name='voicenote',
            name='audio_file',
            field=models.FileField(blank=True, null=True, upload_to='voice_notes/'),
        ),
    ]
