from PyQt5.QtWidgets import QApplication
from interface import Xenon
import sys

if __name__ == '__main__':
    app = QApplication(sys.argv)
    xen = Xenon()
    xen.show()
    sys.exit(app.exec_())
