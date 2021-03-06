Overview
========
Demonstrates a convolutional neural network (CNN) example [1] with the use
of convolution, ReLU activation, pooling and fully-connected functions from
the CMSIS-NN software library. The CNN used in this example is based on
the CIFAR-10 example from Caffe [2]. The neural network consists of
3 convolution layers interspersed by ReLU activation and max pooling layers,
followed by a fully-connected layer at the end. The input to the network is
a 32x32 pixel color image, which is classified into one of the 10 output
classes. 
The example model implementation needs 87 KB to store weights,
40 KB for activations and 6 KB for storing the im2col data.

[1] https://github.com/ARM-software/ML-examples/tree/master/cmsisnn-cifar10
[2] https://github.com/BVLC/caffe

Files:
  main.c - example source code based on a template generated by scripts available at [1]
  ship.bmp - shrinked picture of the object to recognize
    (source: https://en.wikipedia.org/wiki/File:Christian_Radich_aft_foto_Ulrich_Grun.jpg)
  inputs.h - picture from ship.bmp converted into a C language array
    of RGB values using Python with the OpenCV and Numpy packages:
    import cv2
    import numpy as np
    img = cv2.imread('ship.bmp')
    img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
    with open('ship_image.h', 'w') as fout:
      print('#define SHIP_IMG_DATA {', file=fout)
      img.tofile(fout, ',', '%d')
      print('}\n', file=fout)
  weights.h - neural network weights and biases generated by scripts available at [1]
  parameter.h - parameters of the neural network generated by scripts available at [1]


Toolchain supported
===================
- IAR embedded Workbench  8.32.3
- Keil MDK  5.27
- GCC ARM Embedded  8.2.1
- MCUXpresso  11.0.0

Hardware requirements
=====================
- Mini/micro USB cable
- EVKB-IMXRT1050 or EVK-MIMXRT1060 board
- Personal computer

Board settings
==============
No special settings are required.

Prepare the demo
1. Connect a USB cable between the host PC and the OpenSDA USB port on the target board. 
2. Open a serial terminal with the following settings:
   - 115200 baud rate
   - 8 data bits
   - No parity
   - One stop bit
   - No flow control
3. Download the program to the target board.

Prepare the Demo
================

Running the demo
================
The log below shows the output of the demo in the terminal window (compiled with ARM GCC):

CIFAR-10 object recognition example using convolutional neural network
Elapsed time: 48 ms
Predicted class: ship (100% confidence)

Customization options
=====================

