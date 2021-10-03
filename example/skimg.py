# scikit-image 0.18.3 - August 2021

from skimage import data, io, color

image = data.cat()
graypic=color.rgb2gray(image)
io.imshow(graypic)
io.show()