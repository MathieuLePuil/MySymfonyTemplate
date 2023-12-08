# MySymfonyTemplate

[![Version](https://img.shields.io/badge/Version-V1.0.0-blue)](https://github.com/MathieuLePuil/MySymfonyTemplate/releases/tag/v1.0.0)
[![License](https://img.shields.io/badge/License-MIT-green)](https://github.com/MathieuLePuil/MySymfonyTemplate/blob/main/LICENSE.md)
![Symfony](https://img.shields.io/badge/Symfony-V7.0.1-yellow)

This repository is a Symfony 7 template with all the basic elements needed to start a project. The project includes :
* Symfony 7.0.1
* TailwindCSS
* Registration via form
* Registration via oauth
* Connection via form
* Connection via oauth

Table of contents :
1) [Presentation](#présentation)
2) [Installation](#installation)
3) [OAuth](#oauth)

## Presentation

The template contains a single entity: User with the following properties:
* id
* email
* roles
* password
* firstname
* lastname
* username
* profile_picture
* oauth

Account connection is managed in the `SecurityController` and is accessed via the `/login` route. In the case of registration, the route is `/signup`.
Connection can be made via the form on the site or via one of the following social networks:
* Discord
* Github
* Gitlab
* Google

You can add more oauth by following the [KnpU](https://github.com/knpuniversity/oauth2-client-bundle) documentation.

You can also delete them by following this procedure:

1) Delete the `{platform}Connect` and `{platform}ConnectCheck` functions in the `SecurityController`.
2) Delete the configuration lines in `config/packages/knpu_oauth2_client.yaml`.
3) Delete application data in `.env` (or .env.local)

## Installation

Prerequisites :
* PHP 8.2.0 or higher
* Composer
* Symfony CLI
* NodeJS

If you have all the prerequisites, you can start the installation.

1) Clone the repository or download the zip
2) Open your project in your IDE
3) Open a terminal and type `composer install`.
4) Open a terminal and type `npm install`.
5) Set up your .env.local with your database information
6) Open a terminal and type `php bin/console doctrine:database:create`.
7) Open a terminal and type `php bin/console doctrine:schema:update --force`.
8) Set up your .env.local with your [oauth](#oauth) credentials

## OAuth

To use oauth, you need to create an application on the following platforms:
* [Discord](https://discord.com/developers/applications)
* [Github](https://github.com/settings/developers)
* [Gitlab](https://docs.gitlab.com/ee/integration/oauth_provider.html)
* [Google](https://console.cloud.google.com/apis/credentials)

---

Project by [Mathieu Le Puil](https://github.com/MathieuLePuil) - [My Website](https://mathieulp.fr/) -
<a href="mailto:contact@mathieulp.fr" target="_blank">Contact me</a> - [My Twitter](https://twitter.com/MathieuLePuil) - [My LinkedIn](https://www.linkedin.com/in/mathieulepuil/)
