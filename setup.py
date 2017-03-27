#!/usr/bin/env python

from distutils.core import setup

setup(name='simplehttp',
      version='0.1',
      description='sync and async http client with http, https, proxy, auto redirect support',
      author='maliubiao',
      author_email='maliubiao@gmail.com',
      url='http://github.com/maliubiao/simple_http',
      py_modules = ["simple_http", "_http", "async_http"]
     )
