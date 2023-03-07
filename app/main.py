import sys
from PyQt5 import QtWidgets
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import QTreeWidgetItem
from app import design
from app.utils import get_process_table


class DataParser(QThread):
    data_signal = pyqtSignal(dict)

    def __init__(self):
        super(DataParser, self).__init__()
        self._flag = True

    def run(self):
        self.msleep(2000)
        while (self._flag):
            process_table = get_process_table()
            self.data_signal.emit(process_table)
            self.msleep(10000)


class Window(QtWidgets.QMainWindow, design.Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)

        self.tableWidget.setColumnCount(8)
        self.tableWidget.setColumnWidth(0, 150)
        self.tableWidget.setColumnWidth(2, 460)
        self.tableWidget.setHorizontalHeaderLabels(['Process', 'PID', 'Path', 'Packed', 'Signature', 'WX', 'Memory', 'Weight'])

        self.treeWidget.setColumnCount(3)
        self.treeWidget.setColumnWidth(0, 230)
        self.treeWidget.setColumnWidth(1, 700)
        self.treeWidget.setHeaderLabels(['Process', 'Path to DLL', 'Signature'])

        self.thread = DataParser()
        self.thread.data_signal.connect(self.show_processes)
        self.thread.start()

    def show_processes(self, process_table):
        self.tableWidget.setRowCount(0)
        for key, value in process_table.items():
            self.tableWidget.setRowCount(self.tableWidget.rowCount() + 1)
            try:
                self.tableWidget.setItem(self.tableWidget.rowCount()-1, 0, QtWidgets.QTableWidgetItem(value['name']))
                self.tableWidget.setItem(self.tableWidget.rowCount()-1, 1,  QtWidgets.QTableWidgetItem(str(key)))
                self.tableWidget.setItem(self.tableWidget.rowCount() - 1, 2, QtWidgets.QTableWidgetItem(value['pathexe']))
                self.tableWidget.setItem(self.tableWidget.rowCount() - 1, 3, QtWidgets.QTableWidgetItem(value['packexe']))
                self.tableWidget.setItem(self.tableWidget.rowCount() - 1, 4, QtWidgets.QTableWidgetItem(value['signexe']))
                if len(value['wxexe']) == 0:
                    self.tableWidget.setItem(self.tableWidget.rowCount() - 1, 5, QtWidgets.QTableWidgetItem('---'))
                else:
                    self.tableWidget.setItem(self.tableWidget.rowCount() - 1, 5, QtWidgets.QTableWidgetItem(*value['wxexe']))
                self.tableWidget.setItem(self.tableWidget.rowCount() - 1, 6, QtWidgets.QTableWidgetItem(value['memory']))
                self.tableWidget.setItem(self.tableWidget.rowCount()-1, 7, QtWidgets.QTableWidgetItem(str(round(value['weight'], 3))))
            except:
                pass

        self.treeWidget.clear()
        for key, value in process_table.items():
            item = QTreeWidgetItem([value['name']])
            self.treeWidget.addTopLevelItem(item)
            try:
                for dll in process_table[key]['dll']:
                    item.addChild(QTreeWidgetItem(['', dll, process_table[key]['dll'][dll]]))
            except:
                pass


def main():
    app = QtWidgets.QApplication(sys.argv)
    window = Window()
    window.show()
    app.exec_()


if __name__ == '__main__':
    main()