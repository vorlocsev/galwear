# SM-R800 — FlexPMU lifecycle (NON-RELEASE)

База Linux 4.19: 50db73fc799f20a7120a8b5f653b16cc123d856f.
Наследует development/r800-acpm-mif-20261125.

Проверены fs/debugfs/file.c и fs/debugfs/inode.c: debugfs_create_file
использует full proxy; remove дожидается активных операций, но
full_proxy_release обращается к real_fops после удаления. Поэтому
fops теперь статические с owner=THIS_MODULE, а не часть освобождаемого
массива. Lifecycle mutex сериализует probe/remove, второй probe
отклоняется. IO mutex защищает debugfs операции и apm_req. Готовность
публикуется лишь после создания всех файлов; при remove сбрасывается
до ожидания активных операций. Checked MIF mapping инвалидируется
под spinlock до unmap; RTC и FlexPMU освобождаются после debugfs drain.
При частичной ошибке probe удаляются файлы и освобождаются карты.
RTC optional: проверяется размер ресурса. scnprintf ограничивает
форматирование; запись MIF_ALWAYS_ON принимает только 0/1 с
необязательным LF, остальные файлы read-only.

Проверена реконструкция изменённой diff-секции по закреплённой базе
и восемь статических условий на сохранённом патче. Добавлены восемь
Python unittest; сами unittest, kernel build, CI, параллельные
операции на устройстве и fault-injection не запускались.

Ограничения: защита lifetime опирается на full proxy именно этой
базы. Нет доказательства отсутствия аппаратного bus fault или всех
внешних обращений к глобальным указателям. Повторный probe/remove
требует runtime проверки; аппаратные испытания не проведены.
Следующий этап — обновление exact-head integration workflow для
актуальной ветки, проверка полного patch apply и компиляции.
Deep sleep отключён, safe_to_flash=false. Только форк, без PR/main/upstream.
