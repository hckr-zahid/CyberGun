import os
import sys
import math
import random
from PyQt5.QtWidgets import QWidget, QSizePolicy
from PyQt5.QtCore import (QTimer, Qt, QPointF, QRectF, pyqtSlot, 
                          QPropertyAnimation, QEasingCurve, pyqtProperty)
from PyQt5.QtGui import (QColor, QPainter, QPen, QPainterPath, QFont, 
                         QLinearGradient, QRadialGradient, QBrush, QPolygonF, QPixmap)
from core.SignalBus import get_signal_bus
from core.settings import BASE_DIR
class Raindrop:
    def __init__(self, x, y, speed, length, characters, opacity, font_size):
        self.x, self.y, self.speed, self.length, self.opacity, self.font_size = x, y, speed, length, opacity, font_size
        self.chars = random.choices(characters, k=length)
        self.char_offsets = [random.uniform(0, 100) for _ in range(length)]
class BootSplash(QWidget):
    COLOR_BACKGROUND = QColor("#05080c")
    COLOR_HEX_GRID = QColor("#00ffc8")
    COLOR_RAIN_HEAD = QColor("#d0f0d0")
    COLOR_RAIN_BODY = QColor("#00aaff")
    COLOR_GLOW = QColor("#00ffc8")
    COLOR_CYAN = QColor("#00d8ff")
    COLOR_TEXT = QColor("#a0e0a0")
    COLOR_TEXT_BRIGHT = QColor("#ffffff")
    def _get_intro_progress(self): return self._intro_progress
    def _set_intro_progress(self, value): self._intro_progress = value; self.update()
    intro_progress = pyqtProperty(float, _get_intro_progress, _set_intro_progress)
    def _get_outro_progress(self): return self._outro_progress
    def _set_outro_progress(self, value): self._outro_progress = value; self.update()
    outro_progress = pyqtProperty(float, _get_outro_progress, _set_outro_progress)
    def __init__(self, parent=None):
        super().__init__(parent)
        self.signal_bus = get_signal_bus()
        self._intro_progress = 0.0
        self._outro_progress = 0.0
        self.boot_log = [
            "Initializing CyberGun Core Security Engine...",
            "Loading Neural Threat Models...",
            "Connecting to Threat Intelligence Database..."
        ]
        self.current_line_progress = 0
        self._time = 0
        candidate_paths = [
            os.path.join(BASE_DIR, "datasets", "icons", "icon.png"),
            os.path.join(BASE_DIR, "datasets", "icons", "icon.ico"),
            os.path.join(os.path.dirname(__file__), "..", "..", "datasets", "icons", "icon.png"),
            os.path.join(os.path.dirname(__file__), "..", "..", "datasets", "icons", "icon.ico"),
            os.path.join(os.path.dirname(sys.executable), "datasets", "icons", "icon.png"),
            os.path.join(os.path.dirname(sys.executable), "datasets", "icons", "icon.ico"),
            os.path.join(os.path.dirname(sys.executable), "_internal", "datasets", "icons", "icon.png"),
            os.path.join(os.path.dirname(sys.executable), "_internal", "datasets", "icons", "icon.ico"),
        ]
        self.logo_pixmap = QPixmap()
        for cpath in candidate_paths:
            if os.path.exists(cpath):
                pix = QPixmap(cpath)
                if not pix.isNull():
                    self.logo_pixmap = pix
                    break
        self.init_ui()
        self.init_animation()
        self.init_digital_rain()
        self.init_continuous_timer()
        self.signal_bus.splash_updated.connect(self.update_status_text)
        self.signal_bus.loading_finished.connect(self.trigger_outro)
    def init_ui(self):
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setMinimumSize(850, 550)
        self.rain_font = QFont("Consolas", 10)
        self.hud_font = QFont("Consolas", 10)
        self.title_font = QFont("Consolas", 22, QFont.Bold)
        self.subtitle_font = QFont("Consolas", 10, QFont.Bold)
    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.init_digital_rain()
    def init_animation(self):
        self._intro_anim = QPropertyAnimation(self, b'intro_progress', self)
        self._intro_anim.setDuration(4500)
        self._intro_anim.setEasingCurve(QEasingCurve.InOutSine)
        self._intro_anim.setStartValue(0.0)
        self._intro_anim.setEndValue(1.0)
        self._outro_anim = QPropertyAnimation(self, b'outro_progress', self)
        self._outro_anim.setDuration(600)
        self._outro_anim.setEasingCurve(QEasingCurve.InOutQuad)
        self._outro_anim.setStartValue(0.0)
        self._outro_anim.setEndValue(1.0)
        self._outro_anim.finished.connect(self.on_animation_complete)
    def init_digital_rain(self):
        self.raindrops = []
        characters = "0123456789ABCDEF"
        w = max(self.width(), 850)
        h = max(self.height(), 550)
        for opacity, speed_range, size in [(20, (1,3), 8), (45, (3,6), 10), (80, (6,9), 12)]:
            num_columns = int(w // (size * 0.6))
            for i in range(num_columns):
                self.raindrops.append(Raindrop(
                    x=i * (size * 0.6), y=random.randint(-h, 0),
                    speed=random.uniform(*speed_range), length=random.randint(18, 35),
                    characters=characters, opacity=opacity, font_size=size
                ))
    def init_continuous_timer(self):
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.on_tick)
        self.update_timer.start(16)
    def start_animation(self):
        self.show()
        self._intro_anim.start()
    def trigger_outro(self, *args, **kwargs):
        """Thread-safe slot accepting any arguments emitted by loading_finished."""
        self.update_status_text("DATABASE SYNCHRONIZED. SYSTEM ONLINE.")
        QTimer.singleShot(400, self._outro_anim.start)
    @pyqtSlot(str)
    def update_status_text(self, text: str):
        self.boot_log.append(text)
        self.current_line_progress = 0
        if len(self.boot_log) > 6:
            self.boot_log.pop(0)
    @pyqtSlot()
    def on_tick(self):
        self._time += 0.016
        for drop in self.raindrops:
            drop.y += drop.speed
            if drop.y - (drop.length * drop.font_size) > self.height():
                drop.y = random.randint(-180, -40)
        last_line_len = len(self.boot_log[-1]) if self.boot_log else 0
        if self.current_line_progress < last_line_len:
            self.current_line_progress = min(last_line_len, self.current_line_progress + 2)
        self.update()
    @pyqtSlot()
    def on_animation_complete(self):
        self.close()
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(self.rect(), self.COLOR_BACKGROUND)
        self._draw_hex_grid(painter)
        self._draw_digital_rain(painter)
        self._draw_center_brand_and_icon(painter)
        self._draw_hud(painter)
        if self._outro_progress > 0:
            self._draw_outro_effect(painter)
    def _draw_hex_grid(self, painter: QPainter):
        grid_progress = QEasingCurve(QEasingCurve.OutCubic).valueForProgress(min(1.0, self._intro_progress / 0.4))
        if grid_progress <= 0: return
        painter.save()
        painter.translate(self.rect().center())
        hex_size = 45
        pulse = 1.0 + 0.02 * math.sin(self._time * 4)
        painter.setPen(QPen(self.COLOR_HEX_GRID, 1))
        painter.setOpacity(grid_progress * (0.04 + 0.04 * pulse))
        for q in range(-14, 15):
            for r in range(-8, 9):
                x = hex_size * (3./2 * q)
                y = hex_size * (math.sqrt(3)/2 * q + math.sqrt(3) * r)
                poly = QPolygonF()
                for i in range(6):
                    angle = math.pi / 180 * (60 * i)
                    poly.append(QPointF(x + hex_size * math.cos(angle), y + hex_size * math.sin(angle)))
                painter.drawPolygon(poly)
        painter.restore()
    def _draw_digital_rain(self, painter: QPainter):
        for drop in self.raindrops:
            font = QFont("Consolas", drop.font_size)
            painter.setFont(font)
            for i, char in enumerate(drop.chars):
                y_pos = drop.y - (i * drop.font_size)
                if y_pos > self.height() or y_pos < 0: continue
                alpha = drop.opacity
                if i > 0: alpha *= (1 - (i / drop.length))**2
                color = self.COLOR_RAIN_HEAD if i==0 else self.COLOR_RAIN_BODY
                painter.setPen(QColor(color.red(), color.green(), color.blue(), int(alpha)))
                if random.random() < 0.001: painter.setPen(Qt.white)
                painter.drawText(QPointF(drop.x, y_pos), char)
    def _draw_center_brand_and_icon(self, painter: QPainter):
        """Draws the CyberGun shield emblem and glowing brand prominently centered."""
        anim_fade = min(1.0, self._intro_progress / 0.3)
        if anim_fade <= 0: return
        painter.save()
        painter.setOpacity(anim_fade * (1.0 - self._outro_progress))
        cx = self.width() / 2
        cy = self.height() / 2 - 50
        pulse = 1.0 + 0.05 * math.sin(self._time * 6)
        glow_radius = 140 * pulse
        grad = QRadialGradient(QPointF(cx, cy), glow_radius)
        grad.setColorAt(0.1, QColor(0, 255, 200, 110))
        grad.setColorAt(0.5, QColor(0, 170, 255, 45))
        grad.setColorAt(1.0, Qt.transparent)
        painter.setBrush(grad)
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(QPointF(cx, cy), glow_radius, glow_radius)
        painter.setPen(QPen(QColor(0, 255, 200, 140), 1.5, Qt.DashLine))
        painter.setBrush(Qt.NoBrush)
        reticle_r = 95
        painter.drawEllipse(QPointF(cx, cy), reticle_r, reticle_r)
        angle_offset = self._time * 25
        for i in range(8):
            a = math.radians(angle_offset + i * 45)
            x1 = cx + (reticle_r - 6) * math.cos(a)
            y1 = cy + (reticle_r - 6) * math.sin(a)
            x2 = cx + (reticle_r + 6) * math.cos(a)
            y2 = cy + (reticle_r + 6) * math.sin(a)
            painter.setPen(QPen(QColor(0, 216, 255, 180), 2))
            painter.drawLine(QPointF(x1, y1), QPointF(x2, y2))
        icon_size = 130
        if not self.logo_pixmap.isNull():
            scaled = self.logo_pixmap.scaled(
                icon_size, icon_size,
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation
            )
            px = cx - scaled.width() / 2
            py = cy - scaled.height() / 2
            painter.drawPixmap(int(px), int(py), scaled)
        else:
            shield_path = QPainterPath()
            shield_path.moveTo(cx, cy - 55)
            shield_path.lineTo(cx + 45, cy - 30)
            shield_path.lineTo(cx + 35, cy + 35)
            shield_path.lineTo(cx, cy + 60)
            shield_path.lineTo(cx - 35, cy + 35)
            shield_path.lineTo(cx - 45, cy - 30)
            shield_path.closeSubpath()
            painter.setPen(QPen(QColor(0, 255, 200), 2))
            painter.setBrush(QColor(0, 30, 45, 180))
            painter.drawPath(shield_path)
        painter.setFont(self.title_font)
        title_text = "CYBERGUN"
        painter.setPen(QPen(QColor(0, 0, 0, 180), 3))
        painter.drawText(QRectF(cx - 200, cy + 85, 400, 35), Qt.AlignCenter, title_text)
        painter.setPen(QColor(0, 255, 200))
        painter.drawText(QRectF(cx - 200, cy + 85, 400, 35), Qt.AlignCenter, title_text)
        painter.setFont(self.subtitle_font)
        painter.setPen(QColor(0, 170, 255))
        painter.drawText(QRectF(cx - 250, cy + 120, 500, 20), Qt.AlignCenter, "THREAT MITIGATION & FORENSIC SUITE")
        painter.restore()
    def _draw_hud(self, painter: QPainter):
        hud_progress = QEasingCurve(QEasingCurve.OutCubic).valueForProgress(min(1.0, self._intro_progress / 0.35))
        if hud_progress <= 0: return
        painter.save()
        painter.setOpacity(hud_progress * (1.0 - self._outro_progress))
        hud_w, hud_h = min(750, self.width() - 40), 130
        hud_x, hud_y = (self.width() - hud_w) / 2, self.height() - hud_h - 30
        path = QPainterPath()
        c_len = 16
        path.moveTo(hud_x + c_len, hud_y); path.lineTo(hud_x, hud_y); path.lineTo(hud_x, hud_y + c_len)
        path.moveTo(hud_x, hud_y + hud_h - c_len); path.lineTo(hud_x, hud_y + hud_h); path.lineTo(hud_x + c_len, hud_y + hud_h)
        path.moveTo(hud_x + hud_w - c_len, hud_y + hud_h); path.lineTo(hud_x + hud_w, hud_y + hud_h); path.lineTo(hud_x + hud_w, hud_y + hud_h - c_len)
        path.moveTo(hud_x + hud_w, hud_y + c_len); path.lineTo(hud_x + hud_w, hud_y); path.lineTo(hud_x + hud_w - c_len, hud_y)
        painter.setPen(QPen(self.COLOR_GLOW, 2))
        painter.drawPath(path)
        painter.fillRect(QRectF(hud_x, hud_y, hud_w, hud_h), QColor(9, 14, 22, 190))
        painter.setFont(self.hud_font)
        line_height = 18
        for i, line in enumerate(self.boot_log):
            y_line = hud_y + 20 + (i * line_height)
            if i == len(self.boot_log) - 1:
                painter.setPen(self.COLOR_TEXT_BRIGHT)
                visible_text = line[:self.current_line_progress] + ("_" if int(self._time * 4) % 2 == 0 else "")
                painter.drawText(QPointF(hud_x + 18, y_line), f"► {visible_text}")
            else:
                painter.setPen(QColor(100, 160, 120, 170))
                painter.drawText(QPointF(hud_x + 18, y_line), f"  {line}")
        painter.restore()
    def _draw_outro_effect(self, painter: QPainter):
        alpha = int(255 * self._outro_progress)
        painter.fillRect(self.rect(), QColor(5, 8, 12, alpha))