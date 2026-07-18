from __future__ import annotations

from pathlib import Path

from sentinelforge.detectors.django_bola import DjangoBOLADetector


def test_django_detector_empty_project(tmp_path: Path) -> None:
    detector = DjangoBOLADetector()
    findings = detector.scan(tmp_path)
    assert findings == []


def test_django_detector_finds_bola(tmp_path: Path) -> None:
    urls_py = tmp_path / "urls.py"
    urls_py.write_text(
        "from django.urls import path\n"
        "from . import views\n"
        "urlpatterns = [\n"
        "    path('items/<int:pk>/', views.item_detail),\n"
        "]\n"
    )
    views_py = tmp_path / "views.py"
    views_py.write_text(
        "from django.shortcuts import get_object_or_404\n"
        "from rest_framework.views import APIView\n"
        "from rest_framework.response import Response\n"
        "from rest_framework.permissions import IsAuthenticated\n"
        "\n"
        "class ItemDetail(APIView):\n"
        "    permission_classes = [IsAuthenticated]\n"
        "    def get(self, request, pk):\n"
        "        item = get_object_or_404(Item, pk=pk)\n"
        "        return Response({'id': item.id})\n"
    )
    detector = DjangoBOLADetector()
    findings = detector.scan(tmp_path)
    assert len(findings) >= 1
    finding = findings[0]
    assert finding.severity.value == "high"
    assert finding.rule_id == "SF-PY-DJANGO-BOLA-001"
    assert "pk" in finding.evidence["path_params"]


def test_django_detector_skips_authorized(tmp_path: Path) -> None:
    urls_py = tmp_path / "urls.py"
    urls_py.write_text(
        "from django.urls import path\n"
        "from . import views\n"
        "urlpatterns = [\n"
        "    path('items/<int:pk>/', views.item_detail),\n"
        "]\n"
    )
    views_py = tmp_path / "views.py"
    views_py.write_text(
        "from django.shortcuts import get_object_or_404\n"
        "\n"
        "def item_detail(request, pk):\n"
        "    item = get_object_or_404(Item, pk=pk, user=request.user)\n"
        "    return JsonResponse({'id': item.id})\n"
    )
    detector = DjangoBOLADetector()
    findings = detector.scan(tmp_path)
    assert len(findings) == 0


def test_django_detector_skips_no_params(tmp_path: Path) -> None:
    urls_py = tmp_path / "urls.py"
    urls_py.write_text(
        "from django.urls import path\n"
        "from . import views\n"
        "urlpatterns = [\n"
        "    path('items/', views.item_list),\n"
        "]\n"
    )
    views_py = tmp_path / "views.py"
    views_py.write_text(
        "def item_list(request):\n"
        "    return JsonResponse({'items': []})\n"
    )
    detector = DjangoBOLADetector()
    findings = detector.scan(tmp_path)
    assert len(findings) == 0
