# Python Imports
import logging
import json
import os

# Django Imports
from django.db.models import Q
from django.shortcuts import render, reverse, redirect
from django.contrib.auth.decorators import login_required
from django.http import FileResponse

# Project Imports
from .models import JsonName, AvailableLanguage, Tag, TagLanguage

logger = logging.getLogger(__name__)


@login_required("")
def ios_utility_index(request):
    files = JsonName.objects.all()
    return render(request, 'pages/ios_utility/list.html', {
        "names": files,
    })


@login_required("")
def add_json(request):
    messages = []
    files = JsonName.objects.all()
    if dict(request.POST).get("file_name")[0]:
        name = dict(request.POST).get("file_name")[0]
    else:
        messages.append({'tags': 'error', 'message': 'Please Provide Name'})
        return render(request, 'pages/ios_utility/list.html', {
            "names": files,
            "messages": messages
        })

    if JsonName.objects.filter(name=name).exists():
        messages.append({'tags': 'error', 'message': 'Name "{}" Already Exist'.format(name)})
        return render(request, 'pages/ios_utility/list.html', {
            "names": files,
            "messages": messages
        })

    obj = JsonName.objects.create(name=name)
    return redirect(reverse('edit_json', kwargs={'pk': obj.id}))


@login_required("")
def delete_json(request, *args, **kwargs):
    JsonName.objects.filter(id=kwargs['pk']).delete()
    return redirect(reverse('ios_utility_index'))


@login_required("")
def edit_json(request, *args, **kwargs):
    name = JsonName.objects.get(id=kwargs["pk"])
    messages = []
    data = dict(request.POST)
    get_data = dict(request.GET)
    active_languages = name.available_language.all().order_by('langCode')

    # For file name change
    if "file_name" in data:

        if not data["file_name"][0]:
            messages.append({'tags': 'error', 'message': 'Please Provide Name'})
        elif JsonName.objects.filter(name=data["file_name"][0]).exists():
            messages.append({'tags': 'error', 'message': 'Name "{}" Already Exist'.format(name)})
        else:
            name.name = data["file_name"][0]
            name.save()
            messages.append({'tags': 'success', 'message': 'name changed successfully'})

    # For add new tag
    if 'add_tag' in data:

        if Tag.objects.filter(tag=data['tag'][0], module=data['module'][0]).exists():
            messages.append({'tags': 'error', 'message': 'Tag with this name and module already present'})

        else:
            new_tag = Tag.objects.create(name=name, tag=data['tag'][0], module=data['module'][0])
            for active in active_languages:
                if active.langCode in data:
                    TagLanguage.objects.create(tag=new_tag, available_language=active, value=data[active.langCode][0])

            messages.append({'tags': 'success', 'message': "{} with module {} successfully added".
                            format(data['tag'][0], data['module'][0])})

    # For edit tag
    if 'edit_tag_id' in data:
        if Tag.objects.exclude(id=data['edit_tag_id'][0]).filter(tag=data['edit_tag'][0],
                                                                 module=data['edit_module'][0]).exists():
            messages.append({'tags': 'success', 'message': "{} with module {} already present".
                            format(data['edit_tag'][0], data['edit_module'][0])})

        else:
            tag = Tag.objects.get(id=data['edit_tag_id'][0])
            if tag.tag != data['edit_tag'][0] or tag.module != data['edit_module'][0]:
                tag.tag = data['edit_tag'][0]
                tag.module = data['edit_module'][0]
                tag.save()
            for active in active_languages:

                if active.langCode in data:
                    tag_language = TagLanguage.objects.get_or_create(tag=tag, available_language=active)
                    tag_language[0].value = data[active.langCode][0]
                    tag_language[0].save()

    tags = Tag.objects.filter(name=name)

    if 'search_text' in get_data:
        tags = tags.filter(
            Q(tag__icontains=get_data['search_text'][0]) |
            Q(module__icontains=get_data['search_text'][0]) |
            Q(tag_language__value__icontains=get_data['search_text'][0])
        ).distinct()

    return render(request, 'pages/ios_utility/edit_json.html', {
        "name": name,
        "messages": messages,
        "active_languages": active_languages,
        "tags": tags
    })


@login_required("")
def delete_json_tag(request, *args, **kwargs):
    Tag.objects.filter(pk=kwargs['tag_id']).delete()
    return redirect(reverse('edit_json', kwargs={'pk': kwargs['pk']}))


@login_required("")
def json_language_setting(request, *args, **kwargs):
    languages = AvailableLanguage.objects.all().order_by('langCode')
    name = JsonName.objects.get(id=kwargs["pk"])
    active_languages = name.available_language.all()
    messages = []
    post_data = dict(request.POST)
    get_data = dict(request.GET)

    if 'add' in post_data:
        if languages.filter(langCode=post_data['language_code'][0]).exists():
            messages.append({'tags': 'error', 'message': "Language code already present"})

        else:
            AvailableLanguage.objects.create(langCode=post_data['language_code'][0], displayName=post_data
                                             ['display_name'][0], image=post_data['image'][0])
            messages.append({'tags': 'success', 'message': "{} successfully added".
                            format(post_data['language_code'][0])})

    if 'search_text' in get_data:
        languages = languages.filter(
            Q(langCode__icontains=get_data['search_text'][0]) |
            Q(displayName__icontains=get_data['search_text'][0]) |
            Q(image__icontains=get_data['search_text'][0])
        )

    return render(request, 'pages/ios_utility/edit_settings.html', {
        'languages': languages,
        'name': name,
        'messages': messages
    })


@login_required("")
def edit_json_language_setting(request, *args, **kwargs):
    languages = AvailableLanguage.objects.all().order_by('langCode')
    language_obj = AvailableLanguage.objects.get(id=kwargs['language_id'])
    name = JsonName.objects.get(id=kwargs["pk"])
    messages = []
    data = dict(request.POST)

    if 'edit' in data:

        if languages.exclude(id=language_obj.id).filter(langCode=data['language_code'][0]):
            messages.append({'tags': 'error', 'message': "Language code already present"})

        else:
            language_obj.langCode = data['language_code'][0]
            language_obj.displayName = data['display_name'][0]
            language_obj.image = data['image'][0]
            language_obj.save()

    elif 'status_edit' in data:
        if 'status' in data:
            name.available_language.add(language_obj)
            for tag in list(Tag.objects.filter(name=name)):
                TagLanguage.objects.get_or_create(tag=tag, available_language=language_obj)

        else:
            name.available_language.remove(language_obj)

    return render(request, 'pages/ios_utility/edit_settings.html', {
        'languages': languages,
        'name': name,
        'messages': messages
    })


@login_required("")
def delete_json_language_setting(request, *args, **kwargs):
    AvailableLanguage.objects.filter(id=kwargs['language_id']).delete()
    return redirect(reverse('json_language_setting', kwargs={
        'pk': kwargs['pk']
    }))


@login_required("")
def export_json(request, *args, **kwargs):
    name = JsonName.objects.get(id=kwargs['pk'])
    data = dict(request.POST)
    available_language = []
    multi_language = []

    # create json format
    if 'order' in data:
        position = 1
        for lang_code in data['order']:
            language = AvailableLanguage.objects.get(langCode=lang_code)
            available_language.append({
                'langCode': language.langCode,
                'displayName': language.displayName,
                'position': position,
                'image': language.image
            })
            position += 1

    for tag in Tag.objects.filter(name=name):
        translator = []
        if 'order' in data:
            for lang_code in data['order']:
                language = AvailableLanguage.objects.get(langCode=lang_code)
                tag_language = TagLanguage.objects.get(tag=tag, available_language=language)
                translator.append({
                    'code': language.langCode,
                    'value': tag_language.value
                })
        multi_language.append({
            'tag': tag.tag,
            'module': tag.module,
            'translator': translator
        })

    json_dict_data = {
        'availableLanguages': available_language,
        'multiLingual': multi_language
    }

    # path for json
    url = 'dvu/media/language_json/' + name.get_json_name() + '.json'

    # create folder if not present
    if not os.path.exists('dvu/media/language_json'):
        os.mkdir('dvu/media/language_json')

    # send file
    with open(url, 'w') as fp:
        json.dump(json_dict_data, fp)
    response = FileResponse(open(url, 'rb'), as_attachment=True)

    # remove json file from application
    if os.path.exists(url):
        os.remove(url)

    return response


@login_required("")
def import_json(request, *args, **kwargs):
    import_type = dict(request.POST)['json_radio'][0]
    file = dict(request.FILES)['json_file'][0]
    file_data = json.load(file)
    messages = []
    name = JsonName.objects.get(pk=kwargs['pk'])

    name.available_language.clear()
    for active_language in file_data['availableLanguages']:
        language = AvailableLanguage.objects.filter(langCode=active_language['langCode'])
        if language.exists():
            language = language.first()
            pass
        else:
            del active_language['position']
            language = AvailableLanguage(**active_language)
            language.save()
        name.available_language.add(language)

    if import_type == 'replace':
        Tag.objects.filter(name=name).delete()

        for tag in file_data['multiLingual']:
            new_tag = Tag.objects.create(name=name, tag=tag['tag'], module=tag['module'])
            for tag_language in tag['translator']:
                try:
                    language_obj = AvailableLanguage.objects.get(langCode=tag_language['code'])
                    TagLanguage.objects.create(tag=new_tag, available_language=language_obj, value=tag_language['value'])
                except Exception as e:
                    print(str(e))
                    messages.append({'tags': 'error', "message": "code '{}' no available at tag '{}' and module '{}'"
                                    .format(tag_language['code'], tag['tag'], tag['module'])})

    if import_type == 'merge':
        for tag in file_data['multiLingual']:
            new_tag = Tag.objects.get_or_create(name=name, tag=tag['tag'], module=tag['module'])
            for tag_language in tag['translator']:
                try:
                    language_obj = AvailableLanguage.objects.get(langCode=tag_language['code'])
                    tag_language_obj = TagLanguage.objects.get_or_create(tag=new_tag[0], available_language=language_obj)
                    tag_language_obj[0].value = tag_language['value']
                    tag_language_obj[0].save()
                except Exception as e:
                    print(str(e))
                    messages.append({'tags': 'error', "message": "code '{}' no available at tag '{}' and module '{}'"
                                    .format(tag_language['code'], tag['tag'], tag['module'])})

    active_languages = name.available_language.all()
    tags = Tag.objects.filter(name=name)

    return render(request, 'pages/ios_utility/edit_json.html', {
        "name": name,
        "messages": messages,
        "active_languages": active_languages,
        "tags": tags
    })
    # return redirect(reverse('edit_json', kwargs=kwargs))
