Moneysocket Protocol implemented in Python
-----

This is a Python 3 library for consuming and providing Moneysocket connections.

[Donate](https://socket.money/#donate)

Because C-Lightning plugins are best written in Python, the initial set of backend infrastructure components are written in Python and are based off this library. However, the Moneysocket protocol is powerful when used browser and coupled to application UX, for which a fully compatible [JavaScript-based library](https://github.com/moneysocket/js-moneysocket) exists.

Disclaimer!
-----

Moneysocket is still new, under development and is Reckless with your money. Use this stuff at your own risk.

The Version number of this package and on the protocol is set to `0.0.0` for the time being since we anticipate that the protocol specifics will change in breaking ways prior to an 'official' release.


Installing
-----

The `pip3` package manager can install this library into your environment if you point it at the GitHub repo URL:

`$ pip3 install https://github.com/moneysocket/py-moneysocket`

or by just pointing it to a cloned version on you local filesystem:

`$ pip3 install /path/to/py-moneysocket`

This will additionally install the requirements specified in [requirements.txt](requirements.txt).

Depending on what you are doing, it may also be useful to use Python's `virtualenv` utility to install the library and dependencies into a particular 'clean' environment:

`$ virtualenv tempevn`

`$ source tempenv/bin/activate`

`$ pip3 install https://github.com/moneysocket/py-moneysocket`

(do stuff)

`$ deactivate`


Consumers and Providers
-----

A Consumer uses API services provided by a Provider and they must be connected to each other in this way to function.

The primary interaction is via the [OutgoingConsumerStack](moneysocket/stack/consumer.py) and [BidirectionalProviderStack](moneysocket/stack/bidirectional_provider.js) classes.

The BidirectionalProviderStack class is able to both listen for incoming WebSocket connections and make outgoing connections, both in the role of the API provider. This is typically what you will need for a backend server-like application.

The OutgoingConsumerStack is for creating WebSocket connections in a Consumer role. This is typically useful for connecting one type of backend service to another. For example, the [Stablewallet daemon](https://github.com/moneysocket/stabled) consuming the services of a [Terminus](https://github.com/moneysocket/terminus) in the course of providing its higher-level functionality.

These classes are built to be composed into your application which will behave the way you define by your interactions with the library.


Usage
-----

There is no formal API documentation as of yet. It is suggested that you observe the implementation of the [Stablewallet daemon](https://github.com/moneysocket/stabled) for how it interacts with the BidirectionalProviderStack class to accept incoming and create outgoing connections in the Provider role and also for how it uses the OutgoingConsumerStack class to consume connections from a [Terminus](https://github.com/moneysocket/terminus) app.

Additionally, for other custom purposes the layered architecture of the stack provides sub-classes that can be composed into particular purposes. The [Relay](https://github.com/moneysocket/relay) and [Terminus](https://github.com/moneysocket/terminus) apps are such examples where their own Stack classes are composed out of classes of this library their own custom purposes.



Project Links
-----

- [Homepage](https://socket.money)
- [Awesome](https://github.com/moneysocket/awesome-moneysocket)
- [Twitter](https://twitter.com/moneysocket)
- [Telegram](https://t.me/moneysocket)
- [Donate](https://socket.money/#donate)
