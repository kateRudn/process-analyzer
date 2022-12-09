import sys
from PyQt5 import QtWidgets
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMessageBox
from app import design
from app.utils import get_process_table, get_process_info


class Window(QtWidgets.QMainWindow, design.Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)  # инициализация дизайна

        self.processList.itemClicked.connect(self.show_information)

    def show_procceses(self):
        process_table = get_process_table()
        for proc in process_table:
            self.processList.addItem(str(proc['pid']) + ": " + (proc['name']))

    def show_information(self, item):
        self.infromationText.clear()
        process = self.processList.currentItem().text()
        process_table = get_process_table()
        for proc in process_table:
            if proc['pid'] == int(process[:process.find(':')]):
                self.infromationText.appendPlainText("PID: " + str(proc['pid']))
                self.infromationText.appendPlainText("Name: " + proc['name'])
                self.infromationText.appendPlainText("Status: " + str(proc['status']))
                sign, peid_result, sections_WX = get_process_info(proc['pid'])
                self.infromationText.appendPlainText("Signature: " + str(sign))
                self.infromationText.appendPlainText("Peid: " + peid_result)
                self.infromationText.appendPlainText("Section WX: " + str(sections_WX))




def main():
    app = QtWidgets.QApplication(sys.argv)
    window = Window()
    window.show()
    window.show_procceses()
    app.exec_()

if __name__ == '__main__':
    main()