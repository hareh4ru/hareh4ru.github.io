---
layout: null
permalink: /about/
sitemap: false
---
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="refresh" content="0; url={{ '/' | relative_url }}">
    <title>Redirecting…</title>
    <link rel="canonical" href="{{ '/' | absolute_url }}">
  </head>
  <body>
    <p><a href="{{ '/' | relative_url }}">Go to the home page</a></p>
    <script>window.location.replace({{ '/' | relative_url | jsonify }});</script>
  </body>
</html>
