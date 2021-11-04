
from PySide2.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QPushButton,
    QLabel,
    QProgressBar,
    QFileDialog,
    QLineEdit,
    QTextBrowser,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QButtonGroup,
    QRadioButton,
    QGroupBox,
)
from PySide2.QtCore import QSize, Qt
from PySide2.QtGui import QPalette, QColor

import sys
import hashlib
import pathlib


class FilePickWighet(QWidget):

    def __init__(self, *par) -> None:
        super().__init__(*par)
        layout = QHBoxLayout()

        self.label = QLabel('File:')
        self.line = QLineEdit()
        self.button = QPushButton(text='Select')
        self.button.clicked.connect(self.pop)
        layout.addWidget(self.label)
        layout.addWidget(self.line)
        layout.addWidget(self.button)

        self.dialog = QFileDialog()
        self.dialog.setFileMode(QFileDialog.ExistingFile)
        self.dialog.fileSelected.connect(self.setfile)

        self.setLayout(layout)

    def pop(self)-> None:
        self.dialog.exec_()

    def setfile(self, file:str)-> None:
        self.line.setText(file)

    def getfile(self)-> str:
        return self.line.text()

    def init(self)-> None:
        self.line.setText('')


class MainWindow(QMainWindow):

    def __init__(self)->None:
        super().__init__()
        self.setWindowTitle("My Hash")
        self.setFixedSize(QSize(800, 600))
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(229, 217, 237))
        # palette.setColor(QPalette.WindowText, Qt.white)
        self.setPalette(palette)

        self.contain = QWidget()
        layout = QVBoxLayout()
        layout2 = QHBoxLayout()
        layout4 = QGridLayout()

        r1 = QRadioButton('file hash')
        r2 = QRadioButton('files compare')
        self.radio = r1
        self.radio2 = r2
        r1.toggled.connect(self.hash)
        r2.toggled.connect(self.compare)
        layout2.addWidget(r1)
        layout2.addWidget(r2)
        qgb = QGroupBox('Tab')
        qgb.setLayout(layout2)

        layout.addWidget(qgb)
        self.filepick = FilePickWighet()
        self.filepick2 = FilePickWighet()
        layout.addWidget(self.filepick)
        layout.addWidget(self.filepick2)

        self.progressBar = QProgressBar()
        layout.addWidget(self.progressBar)

        self.info = QTextBrowser()
        layout.addWidget(self.info)

        self.go = QPushButton('Run')
        self.go.setFixedSize(QSize(45, 35))
        layout4.addWidget(QLabel(''), 0, 0)
        layout4.addWidget(QLabel(''), 0, 3)
        layout4.addWidget(self.go, 0, 4)
        layout.addLayout(layout4)

        self.contain.setLayout(layout)
        self.setCentralWidget(self.contain)
        self.init()

    def hash(self, checked:bool)->None:
        if checked:
            self.filepick2.hide()
            self.filepick2.init()
            self.info.clear()
            self.progressBar.hide()
            # self.info.clear()

    def compare(self, checked:bool)->None:
        if checked:
            self.filepick2.show()
            self.filepick2.init()
            self.info.clear()
            self.progressBar.hide()

    def init(self)->None:
        self.radio.setChecked(True)
        self.progressBar.hide()
        self.progressBar.setMinimum(0)
        self.progressBar.setMaximum(100)
        self.progressBar.setValue(0)
        # self.info.append('-- INFO --\n')
        self.go.clicked.connect(self.start)

    def fileHash(self)->None:
        # data=[]
        hash_list = ['md5', 'sh1', 'sha256']
        hash_funs = {
            'md5': hashlib.md5,
            'sh1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'blake2b': hashlib.blake2b,
            'blake2s': hashlib.blake2s,
        }
        file_size = 0
        filename = pathlib.Path(self.filepick.getfile())
        msize = filename.stat().st_size
        self.info.append('<font color=blue>%s</font>' %(str(filename.resolve())))
        self.info.append('%.3f MB\n' %(msize/(1024**2)))
        with open(filename, "rb") as f:
            hash_obj = {}
            for key in hash_list:
                hash_obj[key] = hash_funs[key]()

            # Read and update hash string value in blocks of 4K*1024*10(that is 40MB)
            block_size = 4096*1024*10
            i = 0
            for byte_block in iter(lambda: f.read(block_size), b""):
                file_size += block_size
                # i+=1
                # if not i%5:
                #     print('%4.2f%%'%(file_size*100/msize))
                currentValue = file_size*100/msize
                self.progressBar.setValue(currentValue)
                for key in hash_obj:
                    hash_obj[key].update(byte_block)

            for key in hash_obj:
                hex_str = hash_obj[key].hexdigest()
                self.info.append('%-20s %s' % (key, hex_str))
                # data.append(hex_str)
            # self.info.append('\n'+'~'*25)
            self.progressBar.setValue(100)

    def fileCompare(self)->None:
        hash_list = ['md5', 'sh1', 'sha256']
        hash_funs = {
            'md5': hashlib.md5,
            'sh1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'blake2b': hashlib.blake2b,
            'blake2s': hashlib.blake2s,
        }
        file_size = 0
        msize = 0
        data_list = []
        file_list = []
        file_list.append(pathlib.Path(self.filepick.getfile()))
        file_list.append(pathlib.Path(self.filepick2.getfile()))
        for filename in file_list:
            msize += filename.stat().st_size

        for filename in file_list:

            data = []
            self.info.append('<font color=blue>%s</font>' %(str(filename.resolve())))
            self.info.append('%.3f MB\n' %(filename.stat().st_size/(1024**2)))
            with open(filename, "rb") as f:
                hash_obj = {}
                for key in hash_list:
                    hash_obj[key] = hash_funs[key]()

                # Read and update hash string value in blocks of 4K*1024*10(that is 40MB)
                block_size = 4096*1024*10
                for byte_block in iter(lambda: f.read(block_size), b""):
                    file_size += block_size

                    currentValue = file_size*100/msize
                    self.progressBar.setValue(currentValue)
                    for key in hash_obj:
                        hash_obj[key].update(byte_block)

                for key in hash_obj:
                    hex_str = hash_obj[key].hexdigest()
                    self.info.append('%-20s %s' % (key, hex_str))
                    data.append(hex_str)
                self.info.append('\n'+'~'*25)
            data_list.append(data)
        self.progressBar.setValue(100)
        if data_list[0] == data_list[1]:
            self.info.append("<font color=green >\nresult:<b>%10s</b>\n</font>" % 'Yes')
        else:
            self.info.append("<font color=red>\nresult:<b>%10s</b>\n</font>" % 'No')


    def start(self)->None:
        self.info.clear()
        self.progressBar.show()
        if self.radio.isChecked():
            self.fileHash()
        elif self.radio2.isChecked():
            self.fileCompare()


if __name__ == '__main__':

    app = QApplication(sys.argv)

    window = MainWindow()
    window.show()

    # Start the event loop.
    app.exec_()
