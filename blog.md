---
layout: page
title: Blog
subtitle: Mostly old notes on binary exploitation, glibc internals, and CTFs.
permalink: /blog/
nav: blog
---

<ol class="writing-list">
{% for post in site.posts %}
  <li>
    <time datetime="{{ post.date | date_to_xmlschema }}">{{ post.date | date: '%Y.%m' }}</time>
    <div>
      <a class="writing-title" href="{{ post.url | relative_url }}">{{ post.title }}</a>
      <p>{{ post.category }}{% if post.tags.size > 0 %} · {{ post.tags | join: ', ' }}{% endif %}</p>
    </div>
  </li>
{% endfor %}
</ol>
