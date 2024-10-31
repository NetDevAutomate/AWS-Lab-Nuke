# AWS lab_nuke



## Overview

A python program to delete those rouge labs left behind, especially when deployed with IaC and you can no longer find the code to to remove the resources.

This is very much a work in progress and an opportunity for me to improve my Python.

## Purpose

I've been deploying more than a few AWS Cloud WAN labs with AWS Network Firewall, as well as AWS Transit Gateway for migration scenarios, then fogetting about them for a while and having to then go through in order things to delete... so, time to write a bit of code to do this for me.

The longer term plan is to add more classes for more resoruces to clean up resources in an account and maybe cross-account (within an Org) to make cleaning up labs easier without resorting to the (awesome) aws-nuke option.

Why not just use aws-nuke? This is an opportunity for me to improve my Python. I work best when I have a goal to achieve and this was something that would help me day to day and get hands on keyboard to improve my rusty Python.

More documentation to follow on the logic and resources currently covered.

### To Do (Short term)

- [ ] Refactor breaking the code base into modules, likely one class per module, or very inter-related classes per module
- [ ] Add more network resources to delete
- [ ] Add Container resources to delete

## Attribution, License, and Copyright



This tool is licensed under the MIT license. See the [LICENSE](LICENSE) file for more information. 

## Contribute

You can contribute to *aws-nuke* by forking this repository, making your changes and creating a Pull Request against
this repository. If you are unsure how to solve a problem or have other questions about a contributions, please create
a GitHub issue.

