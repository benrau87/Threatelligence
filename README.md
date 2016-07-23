# Threatelligence

<img src="./docs/logo.png" align="right" width="300" />

# Introduction

Threatelligence fetches cyber threat intelligence data from various sources, exposing threats through a search engine. The software provides a variety of dashboards (built using [Kibana](https://www.elastic.co/products/kibana)) used to display data and make searching through security vulnerability data extremely easy.

The project codebase was originally cloned from [syphon1c/Threatelligence](https://github.com/syphon1c/Threatelligence). Kudos!

The [original author](https://github.com/syphon1c) of some of this code has made made it very easy to add your own custom feeds to Threatelligence, automate the fetching of data and removing old data. For more information please see [Customer Feeds](./CustomFeeds.md). You should be able to add all kinds of data (whatever you determine as intelligence) to the underlying index and then display it in the dashboards.
The codebase has been customized however to accomodate specific security notification and requirements.

# Installation

See the [Installation Guide](./Install.md).

# Acknowledgements and Insiptation

The project was originally cloned from [syphon1c/Threatelligence](https://github.com/syphon1c/Threatelligence). Many aspetcs of the code have been edited over time. In order to see a full breakdown of changes consult the [project differential](https://github.com/syphon1c/Threatelligence/compare/master...gfunkoriginal:master).
All additional code present within this codebase is provided by Graeme James McGibbney as per the following permissive, open source license.

```
#Copyright 2016 Graeme James McGibbney
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.
```

