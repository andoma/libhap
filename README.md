# libhap

License: MIT

### Minimalist C library for with Apple HomeKit accessories.

Note: This is still in active development, but works well enough for simple accessories such as a light bulb.

## External dependencies

 * openssl >= 1.1.1
 * avahi-client

Note: OpenSSL 1.1.1 is relatively new and is only available on releases such as Ubuntu 18.04+,  Raspbian Buster, etc.

libhap itself includes these excellent libraries:

 * [nodejs/http-parser](https://github.com/nodejs/http-parser) - MIT License
 * [mjansson/json](https://github.com/mjansson/json) - Public Domain

## Building

    make

## Running example

    ./hap

## Building (and installing) a library

    make solib
    sudo make install # Installs in /usr/local

    make install PREFIX=/some/other/path # Install in ${PREFIX} instead

## Using

The API is documented in [src/hap.h](src/hap.h)

The example in [src/main.c](src/main.c) contains a few examples for how to create:

 * A light-bulb accessory using the `hap_light_builb_create()` convenience function.
 * An RGB light accessory using the `hap_rgb_light_create()` convenience function.
 * A Bridge combining the accessories above.

To create more complex accessories, please read Apple's [Using the HomeKit Accessory Protocol Specification](https://developer.apple.com/support/homekit-accessory-protocol/) to understand the relationship between accessories, services and characteristics.

The plan is to add many more convenience functions to ease usage.


## Made By

Andreas Smas - https://lonelycoder.com - https://twitter.com/andoma
